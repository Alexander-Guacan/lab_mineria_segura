const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

export async function fetchNotes() {
  const res = await fetch(`${API_URL}/notes`);
  const data = await res.json();
  return data
}