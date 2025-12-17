const form = document.getElementById("noteForm");
const notesDiv = document.getElementById("notes");

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

async function fetchNotes() {
  notesDiv.innerHTML = "⏳ Cargando notas...";
  try {
    const res = await fetch(`${API_URL}/notes`);
    const data = await res.json();

    if (data.length === 0) {
      notesDiv.innerHTML = "<p>No hay notas aún.</p>";
      return;
    }

    notesDiv.innerHTML = data
      .map(
        (note) => `
        <div class="note">
          <h3>${note.title}</h3>
          <p>${note.content}</p>
        </div>
      `
      )
      .join("");
  } catch (err) {
    notesDiv.innerHTML = "❌ Error cargando notas";
    console.error(err);
  }
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();

  const title = document.getElementById("title").value;
  const content = document.getElementById("content").value;

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
    fetchNotes();
  } catch (err) {
    alert("❌ Error conectando con el backend");
    console.error(err);
  }
});

// Cargar notas al iniciar
fetchNotes();
