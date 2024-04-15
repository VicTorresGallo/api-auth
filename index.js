'use strict'

// inportaciones

const config = require('./config');
const express = require('express');
const logger = require('morgan');
const mongojs = require('mongojs');
const cors = require('cors');
const PassHelper = require('./helpers/pass.helper');
const tokenHelper = require('./helpers/token.helper');
const moment = require('moment');

const helmet = require('helmet');
var fs = require('fs');
var https = require('https');

// Declaraciones

const port = config.PORT;
const urlDB = config.DB;
const accessToken = config.TOKEN;
const app = express();
const db = mongojs(urlDB); // Enlazamos con la DB
const id = mongojs.ObjectID; // Función para convertir un id textual en un objectID

// Declaraciones para CORS

var allowCrossTokenOrigin = (req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*"); // Permiso a cualquier URL. Mejor acotar
    return next();
};
var allowCrossTokenMethods = (req, res, next) => {
    res.header("Access-Control-Allow-Methods", "*"); // Mejor acotar (GET,PUT,POST,DELETE)
    return next();
};
var allowCrossTokenHeaders = (req, res, next) => {
    res.header("Access-Control-Allow-Headers", "*"); // Mejor acotar (Content-type)
    return next();
};
// middleware

var auth = (req, res, next) => {
    // Comprobamos que han enviado el token tipo Bearer en el Header
    if (!req.headers.authorization) {
      return res.status(401).send({
        result: "KO",
        message:
          "Cabecera de autenticación tipo Bearer no encontrada [Authorization: Bearer jwtToken]",
      });
    }
    const token = req.headers.authorization.split(" ")[1]; // El formato es: Authorization: "Bearer JWT"
    // Comprobamos que han enviado el token
    if (!token) {
      return res.status(401).send({
        result: "KO",
        message:
          "Token de acceso JWT no encontrado dentro de la cabecera [Authorization: Bearer jwtToken]",
      });
    }
    // Verificamos que el token es correcto
    tokenHelper.decodificaToken(token)
      .then((userId) => {
        req.user = {
          id: userId,
          token: token,
        };
        return next();
      })
      .catch((response) => {
        res.status(response.status);
        res.json({
          result: "KO",
          message: response.message,
        });
      });
  };
  
  

// middlewares

app.use(logger('dev')); // probar con: tiny, short, dev, common, combined
app.use(express.urlencoded({ extended: false })); // parse application/x-www-form-urlencoded
app.use(express.json()); // parse application/json
app.use(cors()); // activamos CORS
app.use(allowCrossTokenOrigin); // configuramos origen permitido para CORS
app.use(allowCrossTokenMethods); // configuramos métodos permitidos para CORS
app.use(allowCrossTokenHeaders); // configuramos cabeceras permitidas para CORS
app.use(helmet());// activamos helmet

// routes

app.get('/api/user',(req, res, next) => {
    db.user.find((err, coleccion) => {
        if (err) return next(err);
            res.json(coleccion);
    });
});

app.get('/api/user/:id',(req, res, next) => {
    const elementoId = req.params.id;
    db.user.findOne({ _id: id(elementoId) }, (err, elementoRecuperado) => {
        if (err) return next(err);
            res.json(elementoRecuperado);
    });
});

app.post('/api/user', auth, (req, res, next) => {
    const nuevoElemento = req.body;
    db.user.save(nuevoElemento, (err, coleccionGuardada) => {
        if (err) return next(err);
            res.json(coleccionGuardada);
    });
});

app.put('/api/user/:id', auth, (req, res, next) => {
    const elementoId = req.params.id;
    const nuevosRegistros = req.body;
    db.user.update( { _id: id(elementoId) },
                            { $set: nuevosRegistros },
                            { safe: true, multi: false },
                            (err, result) => {
        if (err) return next(err);
        res.json(result);
    });
});

app.delete('/api/user/:id', auth, (req, res, next) => {
    const elementoId = req.params.id;
    db.user.remove({ _id: id(elementoId) }, (err, resultado) => {
    if (err) return next(err);
        res.json(resultado);
    });
});

app.get('/api/auth',(req, res) => {
    db.user.find({},{_id:0,displayName:1,email:1},(err, coleccion) => {
        if (err) console.error("error get", err);
            res.json(coleccion);
    });
});

app.get('/api/auth/me', auth,(req, res) => {

    db.user.findOne({ _id: id(req.user.id)}, (err, elementoRecuperado) => {
        if (err) return res.status(500).json({
            result: 'KO',
            mensaje: err.message
        });

        res.json({
            result: 'OK',
            usuario: elementoRecuperado
        });
    });
});

// Realiza una identificación o login (signIn).
app.post('/api/auth', (req, res, next) => {
    const email = req.body.email;
    const password = req.body.password;

    if(!email || !password){
        return res.status(400).send( {
            result: 'KO',
            mensaje: ' Faltan datos para el registro '
        });
    }

    db.user.findOne(({email: email}), (err, usuarioExist) => {
        if(err) return  res.status(500).json({
            result: 'KO',
            mensaje: err.message
        });
        if(usuarioExist){
            PassHelper.comparaPassword(password, usuarioExist.password).then(coincide => {
                if(coincide){
                    usuarioExist.lastLogin = moment().unix();
                    db.user.update({email: email},
                        {$set:
                            {
                            "lastLogin": moment().unix()
                        }
                    }, (err) => {
                    if(err) return next(err);
                    const token = tokenHelper.creaToken(usuarioExist);
                    const resultado = {
                        result: "OK",
                        token: token,
                        usuario: usuarioExist
                    };
                    res.json(resultado);
                    });
                }else{
                    res.status(401).json({
                        status: 401,
                        result: 'KO',
                        mensaje: 'No coincide la contraseña con la del usuario'
                    });
                }
            }).catch(error => { //Sin catch no llega la rspuesta porque se queda en el then
                console.error('Error con las contraseñas', error);
                return res.status(500).json({
                    result:'KO',
                    mensaje: 'Error procesando solicitud'
                });
            });
        }else{
            //no existe el usuario, por lo q se envia una respuesta
            return res.status(404).json({
                result:'KO',
                mensaje:'Usuario no encontrado'
            });
        }
    });
});


//Hacemos un SignUP()
app.post('/api/auth/reg',(req, res) => {
    const { name, email, password } = req.body;
    // Verificar que ha llegado un nombre, email y contraseña
    if (!name || !email || !password) {
        return res.status(400).json({
          result: "NO",
          msg: "Faltan datos obligatorios, datos : name, email, password",
        });
    }
    // Verificación de usuario existente
    db.user.findOne({ email }, (err, usuarioEncontrado) => {
        if (err)
        return res.status(500).json({
            result: "NO",
            msg: "Error servidor",
        });

        if (usuarioEncontrado)
        return res.status(409).json({
            result: "NO",
            msg: "Ya existe un usuario con ese email",
        });

        // Encriptación de password
        PassHelper.encriptaPassword(password).then (hash => {
            // Creación del nuevo usuario
            const nuevoUsuario = {
                displayName: name,
                email: email,
                password: hash,
                signupDate: moment().unix(),
                lastLogin: moment().unix(),
            };
            
            // Guardado del usuario
            db.user.save(nuevoUsuario, (err, userGuardado) => {
                if (err) {
                res.status(500).json({
                    result: "NO",
                    msg: "Error servidor",
                });
                }
                // Generación del token
                const token = tokenHelper.creaToken(nuevoUsuario);
                res.json({result: 'OK', token, usuario: userGuardado});
            });
        });
    });
});

// Iniciamos la aplicación

https.createServer({
        cert: fs.readFileSync('./cert/cert.pem'),
        key: fs.readFileSync('./cert/key.pem')
    },app).listen(port, () => {
    console.log(`API RESTful CRUD ejecutándose en https://localhost:${port}/api/{col}/{id}`);
}); 