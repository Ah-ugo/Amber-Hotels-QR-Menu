from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
import cloudinary
import cloudinary.uploader
import qrcode
from io import BytesIO
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import smtplib
from email.mime.text import MIMEText
import os
import asyncio
from dotenv import load_dotenv
load_dotenv()

app = FastAPI(title="Hotel Digital Menu System")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
CLOUDINARY_CLOUD_NAME = os.getenv("CLOUDINARY_CLOUD_NAME")
CLOUDINARY_API_KEY = os.getenv("CLOUDINARY_API_KEY")
CLOUDINARY_API_SECRET = os.getenv("CLOUDINARY_API_SECRET")
JWT_SECRET = os.getenv("JWT_SECRET", "your-secret-key")
EMAIL_HOST = os.getenv("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = os.getenv("EMAIL_PORT", 587)
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")
BASE_URL = os.getenv("BASE_URL", "http://amberhotels.com/menu")

# MongoDB setup
client = AsyncIOMotorClient(MONGODB_URL)
db = client.hotel_menu

# Cloudinary setup
cloudinary.config(
    cloud_name=CLOUDINARY_CLOUD_NAME,
    api_key=CLOUDINARY_API_KEY,
    api_secret=CLOUDINARY_API_SECRET
)

# JWT setup
SECRET_KEY = JWT_SECRET
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Pydantic Models
class MenuItem(BaseModel):
    name: str
    price: float
    category: str
    image_url: Optional[str] = None


class OrderItem(BaseModel):
    item_id: str
    quantity: int


class Order(BaseModel):
    table_number: int
    items: List[OrderItem]
    notes: Optional[str] = None
    status: str = "pending"
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Table(BaseModel):
    table_number: int
    qr_code: Optional[str] = None
    qr_image_url: Optional[str] = None  # New field for Cloudinary QR code URL
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Admin(BaseModel):
    username: str
    email: EmailStr
    password: Optional[str] = None


class AdminInDB(Admin):
    hashed_password: str


class Token(BaseModel):
    access_token: str
    token_type: str


# Helper Functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


async def get_current_admin(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    admin = await db.admins.find_one({"username": username})
    if admin is None:
        raise credentials_exception
    return admin


async def send_email(subject: str, body: str, to_email: str):
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_USER
    msg["To"] = to_email

    try:
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
    except Exception as e:
        print(f"Email sending failed: {str(e)}")


# Authentication Routes
@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    admin = await db.admins.find_one({"username": form_data.username})
    if not admin or not verify_password(form_data.password, admin["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = jwt.encode({"sub": form_data.username}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/register")
async def register(
        username: str = Form(...),
        email: EmailStr = Form(...),
        password: str = Form(...)
):
    if await db.admins.find_one({"$or": [{"username": username}, {"email": email}]}):
        raise HTTPException(status_code=400, detail="Username or email already registered")

    hashed_password = get_password_hash(password)
    admin = {
        "username": username,
        "email": email,
        "hashed_password": hashed_password
    }
    await db.admins.insert_one(admin)
    return {"message": "Admin registered successfully"}


# Menu Management Routes
@app.post("/menu")
async def create_menu_item(
        name: str = Form(...),
        price: float = Form(...),
        category: str = Form(...),
        file: UploadFile = File(...),
        admin: dict = Depends(get_current_admin)
):
    try:
        upload_result = cloudinary.uploader.upload(file.file, folder="hotel_menu")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Image upload failed: {str(e)}")

    item_dict = {
        "name": name,
        "price": price,
        "category": category,
        "image_url": upload_result["secure_url"]
    }
    result = await db.menus.insert_one(item_dict)
    item_dict["_id"] = str(result.inserted_id)
    return item_dict


@app.get("/menu", response_model=List[MenuItem])
async def get_menu():
    items = await db.menus.find().to_list(100)
    for item in items:
        item["_id"] = str(item["_id"])
    return items


@app.patch("/menu/{id}")
async def update_menu_item(
        id: str,
        name: Optional[str] = Form(None),
        price: Optional[float] = Form(None),
        category: Optional[str] = Form(None),
        file: UploadFile = File(None),
        admin: dict = Depends(get_current_admin)
):
    item_dict = {}
    if name:
        item_dict["name"] = name
    if price is not None:
        item_dict["price"] = price
    if category:
        item_dict["category"] = category
    if file:
        try:
            upload_result = cloudinary.uploader.upload(file.file, folder="hotel_menu")
            item_dict["image_url"] = upload_result["secure_url"]
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Image upload failed: {str(e)}")

    if not item_dict:
        raise HTTPException(status_code=400, detail="No fields provided for update")

    result = await db.menus.update_one({"_id": ObjectId(id)}, {"$set": item_dict})
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Item not found")

    updated_item = await db.menus.find_one({"_id": ObjectId(id)})
    updated_item["_id"] = str(updated_item["_id"])
    return updated_item


@app.delete("/menu/{id}")
async def delete_menu_item(id: str, admin: dict = Depends(get_current_admin)):
    result = await db.menus.delete_one({"_id": ObjectId(id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"message": "Item deleted"}


# Table Management Routes
@app.post("/table")
async def create_table(table_number: int = Form(...), admin: dict = Depends(get_current_admin)):
    if await db.tables.find_one({"table_number": table_number}):
        raise HTTPException(status_code=400, detail="Table number already exists")

    table_dict = {
        "table_number": table_number,
        "created_at": datetime.utcnow()
    }
    result = await db.tables.insert_one(table_dict)
    table_dict["_id"] = str(result.inserted_id)
    return table_dict


@app.get("/tables")
async def get_tables(admin: dict = Depends(get_current_admin)):
    tables = await db.tables.find().to_list(100)
    for table in tables:
        table["_id"] = str(table["_id"])
    return tables


@app.delete("/table/{table_number}")
async def delete_table(table_number: int, admin: dict = Depends(get_current_admin)):
    result = await db.tables.delete_one({"table_number": table_number})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Table not found")
    return {"message": "Table deleted"}


# Order Management Routes
@app.post("/order")
async def create_order(order: Order):
    if not await db.tables.find_one({"table_number": order.table_number}):
        raise HTTPException(status_code=400, detail="Table not found")

    for item in order.items:
        if not await db.menus.find_one({"_id": ObjectId(item.item_id)}):
            raise HTTPException(status_code=400, detail=f"Menu item {item.item_id} not found")

    order_dict = order.dict()
    order_dict["created_at"] = datetime.utcnow()
    result = await db.orders.insert_one(order_dict)
    order_dict["_id"] = str(result.inserted_id)

    admins = await db.admins.find().to_list(100)
    for admin in admins:
        await send_email(
            subject="New Order Received",
            body=f"New order for table {order.table_number}. Order ID: {order_dict['_id']}",
            to_email=admin["email"]
        )
    return order_dict


@app.get("/orders")
async def get_all_orders(admin: dict = Depends(get_current_admin)):
    orders = await db.orders.find().to_list(100)
    for order in orders:
        order["_id"] = str(order["_id"])
    return orders


@app.get("/orders/{table_number}")
async def get_table_orders(table_number: int, admin: dict = Depends(get_current_admin)):
    if not await db.tables.find_one({"table_number": table_number}):
        raise HTTPException(status_code=404, detail="Table not found")
    orders = await db.orders.find({"table_number": table_number}).to_list(100)
    for order in orders:
        order["_id"] = str(order["_id"])
    return orders


@app.patch("/order/{id}/status")
async def update_order_status(id: str, status: str = Form(...), admin: dict = Depends(get_current_admin)):
    valid_statuses = ["pending", "preparing", "served"]
    if status not in valid_statuses:
        raise HTTPException(status_code=400, detail="Invalid status")
    result = await db.orders.update_one(
        {"_id": ObjectId(id)},
        {"$set": {"status": status}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Order not found")
    return {"message": "Status updated"}


# QR Code Generation
@app.get("/generate-qr/{table_number}")
async def generate_qr(table_number: int):
    if not await db.tables.find_one({"table_number": table_number}):
        raise HTTPException(status_code=404, detail="Table not found")

    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(f"{BASE_URL}?table={table_number}")
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buffer = BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)

    await db.tables.update_one(
        {"table_number": table_number},
        {"$set": {"qr_code": buffer.getvalue().hex()}}
    )

    return {"qr_code": buffer.getvalue().hex()}


@app.get("/qr-image/{table_number}")
async def get_qr_image(table_number: int):
    table = await db.tables.find_one({"table_number": table_number})
    if not table:
        raise HTTPException(status_code=404, detail="Table not found")

    # Return cached QR code URL if it exists
    if table.get("qr_image_url"):
        return {"qr_image_url": table["qr_image_url"]}

    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(f"{BASE_URL}?table={table_number}")
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    # Save to buffer
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)

    # Upload to Cloudinary
    try:
        upload_result = cloudinary.uploader.upload(
            buffer,
            folder="hotel_menu/qr_codes",
            public_id=f"table_{table_number}_qr",
            overwrite=True
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"QR code upload failed: {str(e)}")

    # Store URL in table
    qr_image_url = upload_result["secure_url"]
    await db.tables.update_one(
        {"table_number": table_number},
        {"$set": {"qr_image_url": qr_image_url}}
    )

    return {"qr_image_url": qr_image_url}


# Daily Menu Update Reminder
async def send_daily_reminder():
    while True:
        now = datetime.utcnow()
        if now.hour == 8 and now.minute == 0:
            admins = await db.admins.find().to_list(100)
            for admin in admins:
                await send_email(
                    subject="Daily Menu Update Reminder",
                    body="Please review and update the menu for today.",
                    to_email=admin["email"]
                )
        await asyncio.sleep(60)


@app.on_event("startup")
async def startup_event():
    admin_count = await db.admins.count_documents({})
    if admin_count == 0:
        default_admin = {
            "username": "admin",
            "email": "admin@amberhotels.com",
            "hashed_password": get_password_hash("admin123")
        }
        await db.admins.insert_one(default_admin)

    asyncio.create_task(send_daily_reminder())