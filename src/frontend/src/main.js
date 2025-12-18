import { fetchNotes } from "./api";

const form = document.querySelector("#note-form");
const notesDiv = document.querySelector("#notes");

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

function clearNotes() {
  notesDiv.textContent = "";
}

function renderMessage(message) {
  clearNotes();
  const p = document.createElement("p");
  p.textContent = message;
  notesDiv.append(p);
}

function renderNote(note) {
  const noteDiv = document.createElement("div");
  noteDiv.classList.add("note");

  const title = document.createElement("h3");
  title.textContent = note.title;

  const content = document.createElement("p");
  content.textContent = note.content;

  noteDiv.append(title, content);
  notesDiv.append(noteDiv);
}

async function loadNotes() {
  renderMessage("⏳ Cargando notas...");

  try {
    const data = await fetchNotes();

    if (data.length === 0) {
      renderMessage("No hay notas aún.");
      return;
    }

    clearNotes();
    data.forEach(renderNote);

  } catch (err) {
    renderMessage("❌ Error cargando notas");
    console.error(err);
  }
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();

  const title = document.querySelector("#title").value;
  const content = document.querySelector("#content").value;

  try {
    const res = await fetch(`${API_URL}/notes`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ title, content }),
    });

    if (!res.ok) {
      alert("Error guardando la nota");
      return;
    }

    form.reset();
    loadNotes();

  } catch (err) {
    alert("❌ Error conectando con el backend");
    console.error(err);
  }
});

loadNotes();
