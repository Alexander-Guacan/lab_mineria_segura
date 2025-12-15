var express = require('express');
var app = express();

// Configuración básica
var PORT = 3000;

app.get('/create-session', function(req, res) {
    var userId = req.query.id;
    var sessionToken = "";
    var charSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    
    // Bucle usando 'var' para el iterador
    for (var i = 0; i < 20; i++) {
        // VULNERABILIDAD REAL: Uso de Math.random (débil) en lugar de crypto
        var randomPos = Math.floor(Math.random() * charSet.length);
        sessionToken += charSet.charAt(randomPos);
    }

    // Bloque condicional para probar el 'Hoisting' de var
    if (sessionToken.length === 20) {
        // Con 'var', esta variable sube al inicio de la función (hoisting)
        // Con 'let' o 'const', esta variable moriría al cerrar la llave '}'
        var logMessage = "Token generado para usuario: " + userId;
    }

    // Accedemos a logMessage fuera del bloque if.
    // Esto es válido en JS antiguo con var, pero mala práctica.
    console.log(logMessage); 

    res.json({
        id: userId,
        token: sessionToken,
        status: "active"
    });
});

app.listen(PORT, function() {
    var startMessage = "Servidor corriendo en puerto " + PORT;
    console.log(startMessage);
});