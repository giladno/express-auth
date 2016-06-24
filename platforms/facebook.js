'use strict';
const request = require('request');

module.exports = token=>new Promise((resolve, reject)=>request({
    url: 'https://graph.facebook.com/v2.6/me',
    qs: {access_token: token, fields: 'name,email'},
    json: true,
}, (err, res, json)=>{
    if (err)
        return reject(err);
    resolve(Object.assign(json||{}, {access_token: token}));
}));
