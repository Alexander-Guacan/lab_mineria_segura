const express = require('express');
const { exec } = require('child_process');
const app = express();

app.get('/ping', (req, res) => {
    const address = req.query.address;

    // VULNERABILIDAD: Se concatena el input directamente al comando
    // CWE-78: Improper Neutralization of Special Elements used in an OS Command
    exec(`ping -c 1 ${address}`, (error, stdout, stderr) => {
        if (error) {
            return res.status(500).send(`Error: ${error.message}`);
        }
        res.send(`Resultado: ${stdout}`);
    });
});

app.listen(3000, () => {
    console.log('Servidor vulnerable corriendo en puerto 3000');
});