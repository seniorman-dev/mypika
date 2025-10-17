from django.conf import settings
import socketio
from django.contrib.auth import get_user_model
from django.db.models import Q, OuterRef, Subquery
from asgiref.sync import sync_to_async
import jwt
from .models import Message
from .serializers import BasicUserSerializer, MessageSerializer  # If available






User = get_user_model()

sio = socketio.AsyncServer(async_mode="asgi", cors_allowed_origins="*")

# Store connected users {user_id: sid}
connected_users = {}




# -------------------------------------
# 🔹 JWT AUTHENTICATION HELPER
# -------------------------------------
def get_token_from_headers(environ):
    """
    Extracts Bearer token from incoming socket connection headers.
    """
    headers = environ.get("asgi.scope", {}).get("headers", [])
    for key, value in headers:
        if key == b'authorization':  # header key is lowercase and bytes
            auth_header = value.decode()
            if auth_header.startswith("Bearer "):
                return auth_header.split("Bearer ")[1]
    return None


async def get_user_from_token(token: str):
    """
    Decode JWT and return user instance.
    """
    try:
        payload: dict = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get("user_id")
        if not user_id:
            return None
        user = await sync_to_async(User.objects.get)(id=user_id)
        return user
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, User.DoesNotExist):
        return None


# -------------------------------------
# 🔹 CONNECTION EVENTS
# -------------------------------------
@sio.event
async def connect(sid, environ, auth):
    """
    Authenticate user via Bearer token from headers.
    """
    print(f"Client attempting connection: {sid}")

    token = get_token_from_headers(environ)
    if not token:
        print("❌ Missing or invalid token header.")
        return False  # Reject connection

    user = await get_user_from_token(token)
    if not user:
        print("❌ Authentication failed.")
        return False  # Reject connection

    # Save connection
    connected_users[str(user.id)] = sid
    sio.save_session(sid, {"user": user})
    print(f"✅ User {user.email} connected with SID {sid}")


@sio.event
async def disconnect(sid):
    """
    Remove disconnected users from memory.
    """
    print(f"Client disconnected: {sid}")
    for uid, stored_sid in list(connected_users.items()):
        if stored_sid == sid:
            del connected_users[uid]
            print(f"❌ User {uid} went offline")





# -------------------------------------
# 🔹 SEND MESSAGE EVENT
# -------------------------------------
@sio.event
async def send_message(sid, data: dict):
    """
    data = {
      "sender_id": 1,
      "receiver_id": 2,
      "content": "Hello Admin Fazola!",
      "type": "text",
      "is_read": false
    }
    """
    sender_id = data["sender_id"]
    recipient_id = data["receiver_id"]
    message = data["content"]
    msg_type = data["type"]
    is_read = data["is_read"]

    # Fetch sender and recipient
    sender = await sync_to_async(User.objects.get)(id=sender_id)
    receiver = await sync_to_async(User.objects.get)(id=recipient_id)

    # Save the message
    msg = await sync_to_async(Message.objects.create)(
        sender=sender,
        receiver=receiver,
        content=message,
        type=msg_type,
        is_read=is_read,
    )

    # Build payload
    payload = {
        "id": msg.id,
        "content": msg.content,
        "type": msg.type,
        "is_read": msg.is_read,
        "created_at": msg.timestamp.isoformat(),
        "sender": {
            "id": sender.id,
            "first_name": sender.first_name,
            "last_name": sender.last_name,
            "email": sender.email,
        },
        "receiver": {
            "id": receiver.id,
            "first_name": receiver.first_name,
            "last_name": receiver.last_name,
            "email": receiver.email,
        },
    }

    # Deliver to recipient if online
    recipient_sid = connected_users.get(str(recipient_id))
    if recipient_sid:
        await sio.emit("receive_message", payload, to=recipient_sid)

    # Echo to sender as well
    await sio.emit("receive_message", payload, to=sid)



@sio.event
async def mark_as_read(sid, data: dict):
    """
    data = {"sender_id": 1, "receiver_id": 2}
    """
    sender_id = data["sender_id"]
    receiver_id = data["receiver_id"]
    
    await sync_to_async(Message.objects.filter(
        sender_id=sender_id, 
        receiver_id=receiver_id, 
        is_read=False
    ).update)(is_read=True)


    # Optionally notify the sender that messages were read
    '''sender_sid = connected_users.get(str(sender_id))
    if sender_sid:
        await sio.emit("messages_read", {"receiver_id": receiver_id}, to=sender_sid)'''
        


@sio.event
async def get_chat_history(sid, data: dict):
    """
    Fetch all chat partners and last messages for a user.

    data = { "user_id": 1 }
    """
    user_id = data.get("user_id")

    # Get logged-in user
    user = await sync_to_async(User.objects.get)(id=user_id)

    # Get all chat pairs for this user
    chat_user_ids = await sync_to_async(list)(
        Message.objects.filter(Q(sender=user) | Q(receiver=user))
        .values_list("sender", "receiver")
    )

    # Flatten IDs
    user_ids = set()
    for sender_id, receiver_id in chat_user_ids:
        if sender_id != user.id:
            user_ids.add(sender_id)
        if receiver_id != user.id:
            user_ids.add(receiver_id)

    # Subquery to fetch latest message between user and each chat partner
    latest_message_subquery = Message.objects.filter(
        Q(sender=user, receiver=OuterRef("pk")) | Q(sender=OuterRef("pk"), receiver=user)
    ).order_by("-created_at")

    # Fetch all chat users with their latest message timestamps
    chat_users = await sync_to_async(list)(
        User.objects.filter(id__in=user_ids)
        .annotate(
            last_message_id=Subquery(latest_message_subquery.values("id")[:1]),
            last_message_time=Subquery(latest_message_subquery.values("timestamp")[:1])
        )
        .order_by("-last_message_time")
    )

    chat_list = []

    # Build chat list with last message + unread count
    for u in chat_users:
        last_message = await sync_to_async(Message.objects.filter(id=u.last_message_id).first)()
        unread_count = await sync_to_async(Message.objects.filter(
            sender=u, receiver=user, is_read=False
        ).count)()

        chat_list.append({
            "user": {
                "id": u.id,
                "first_name": u.first_name,
                "last_name": u.last_name,
                "email": u.email,
            },
            "last_message": {
                "id": last_message.id,
                "content": last_message.content,
                "type": last_message.type,
                "timestamp": last_message.timestamp.isoformat(),
                "sender_id": last_message.sender.id,
                "receiver_id": last_message.receiver.id,
            } if last_message else None,
            "unread_count": unread_count,
        })

    # Emit the chat list back to the user
    await sio.emit("chat_history", {"chats": chat_list}, to=sid)
    print(f" Sent chat history to user {user_id}")
