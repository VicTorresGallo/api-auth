'use strict'
const bcrypt = require('bcrypt');
/*Formato de un hash con salt:

$2b$[cost]$[22 character salt][31 character hash]
// Ejemplo:
//
        '$2b$10$G1DDAoljDq90F9H/9uH6z.NQpkg4lbVVC/v4RTLQ87j1.6VDbpbTK'
         \__/\/ \____________________/\_____________________________/
//       Alg Cost       Salt                       Hash
*/

function encriptaPassword( password ) {
    return bcrypt.hash(password, 10);
}
// Devuelve true o false
function comparaPassword( password, hash ) {
    return bcrypt.compare(password, hash);
}
module.exports = {
    encriptaPassword,
    comparaPassword
};