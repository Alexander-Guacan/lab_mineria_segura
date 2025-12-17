from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import os
import dotenv

dotenv.load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        os.getenv("API_CLIENT"),
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class Note(BaseModel):
    title: str
    content: str

notes = []

@app.get("/")
def root():
    return {"status": "ok"}

@app.get('/greeting')
def greeting():
    return "Hello world"

@app.get("/notes")
def get_notes():
    return notes

@app.post("/notes")
def add_note(note: Note):
    if len(notes) > 50:
        notes.clear()

    notes.append(note)
    return {"message": "Note added"}
