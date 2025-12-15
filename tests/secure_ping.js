const express = require('express');
const { execFile } = require('child_process');
const app = express();

// Validación simple de formato IP
const isValidIP = (ip) => {
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    return ipRegex.test(ip);
};

app.get('/ping', (req, res) => {
    const address = req.query.address;

    // CAPA 1: Validación de entrada (Input Validation)
    if (!isValidIP(address)) {
        return res.status(400).send('Dirección IP inválida');
    }

    // CAPA 2: Uso de execFile en lugar de exec
    // Esto pasa los argumentos como un array, evitando la interpretación de shell (; | &&)
    execFile('ping', ['-c', '1', address], (error, stdout, stderr) => {
        if (error) {
            return res.status(500).send('Error al ejecutar ping');
        }
        res.send(`Resultado: ${stdout}`);
    });
});

app.listen(3000, () => {
    console.log('Servidor seguro corriendo en puerto 3000');
});