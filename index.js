'use strict';
const assert = require('assert');
const bcrypt = require('bcryptjs');
const express = require('express');
const crypto = require('crypto');
const base58 = require('bs58');

module.exports = opt=>{
    assert(opt&&opt.cookie&&opt.cookie.secret, 'missing cookie-session secret');
    assert(opt.collection, 'missing mongo collection');
    opt.bcrypt = opt.bcrypt||10;
    opt.middleware = opt.middleware!==undefined ? opt.middleware : true;
    opt.json = opt.json!==undefined ? opt.json : !opt.middleware;
    const token = ()=>new Promise((resolve, reject)=>crypto.randomBytes(opt.token||32, (err, buf)=>{
        if (err)
            return reject(err);
        resolve(base58.encode(buf));
    }));
    const hash = password=>new Promise((resolve, reject)=>{
        bcrypt.hash(password||'', opt.bcrypt, (err, hash)=>{
            if (err)
                return reject(err);
            resolve(hash);
        });
    });
    const compare = (p1, p2)=>new Promise((resolve, reject)=>{
        bcrypt.compare(p1||'', p2||'', (err, res)=>{
            if (err)
                return reject(err);
            resolve(res);
        });
    });
    const platforms = require('require-all')(require('path').join(__dirname, 'platforms'));
    const app = express();
    app.use(require('cookie-session')({
        name: opt.cookie.name||'eauth',
        secret: opt.cookie.secret,
        secureProxy: opt.cookie.secureProxy!==undefined ?
            opt.cookie.secureProxy : process.env.NODE_ENV=='production',
        maxAge: opt.cookie.age||365*86400000,
    }));
    app.use(require('body-parser').urlencoded({extended: true}));
    if (opt.json)
        app.use(require('body-parser').json());
    app.use((req, res, next)=>{
        req.user = null;
        const token = req.session.token||(opt.stateless&&(req.query.token||req.body.token));
        if (!token)
            return next();
        opt.collection.findOne({token: token}).then(user=>{
            req.user = user;
            next();
        }).catch(next);
    });
    app.post('/login', (req, res, next)=>{
        req.user = null;
        if (req.body.password)
        {
            let query = {};
            if (req.body.email)
                query.email = req.body.email;
            else if (req.body.username)
                query.username = req.body.username;
            else
                return res.status(400).end();
            return opt.collection.findOne(query).then(user=>{
                if (!user || !user.password)
                    return;
                return compare(req.body.password, user.password).then(result=>result&&user);
            }).then(user=>{
                if (!user)
                    return opt.middleware ? next() : res.status(401).end();
                if (opt.verify && !user.verified)
                {
                    return token().then(token=>opt.collection.findAndModify({
                        query: {_id: user._id},
                        update: {$set: {verify: {
                            token: token,
                            timestamp: new Date(),
                            ua: req.headers['user-agent'],
                        }}},
                        new: true,
                    })).then(user=>opt.verify(user)).then(()=>{
                        if (opt.middleware)
                            return next();
                        res.status(403).end();
                    });
                }
                req.user = user;
                req.session.token = user.token.token;
                if (opt.middleware)
                    return next();
                res.json({token: user.token.token});
            }).catch(next);
        }
        for (let name in platforms)
        {
            if (!req.body[name])
                continue;
            return platforms[name](req.body[name]).then(user=>{
                if (!user || !user.email)
                    return;
                const update = {$set: {}};
                update.$set[name] = user;
                return opt.collection.findAndModify({
                    query: {email: user.email},
                    update: update,
                    new: true,
                });
            }).then(user=>{
                if (!user)
                    return opt.middleware ? next() : res.status(401).end();
                req.user = user;
                req.session.token = user.token.token;
                if (opt.middleware)
                    return next();
                res.json({token: user.token.token});
            });
        }
        res.status(400).end();
    });
    app.post('/register', (req, res, next)=>{
        req.user = null;
        if (!req.body.email)
            return res.status(400).end();
        if (opt.username && !req.body.username)
            return res.status(400).end();
        Promise.all([hash(req.body.password), token(), opt.verify && token()]).then(result=>{
            let user = {
                email: req.body.email,
                password: result[0],
                ip: req.ip,
                ua: req.headers['user-agent'],
                random: Math.random(),
                token: {
                    token: result[1],
                    timestamp: new Date(),
                    ua: req.headers['user-agent'],
                },
            };
            if (req.body.username)
                user.username = req.body.username;
            if (opt.verify)
            {
                user.verify = {
                    token: result[2],
                    timestamp: new Date(),
                    ua: req.headers['user-agent'],
                };
            }
            return opt.collection.insert(user);
        }).then(user=>{
            req.user = user;
            if (opt.verify)
            {
                return opt.verify(user).then(()=>{
                    if (opt.middleware)
                        return next();
                    res.status(202).end();
                });
            }
            req.session.token = user.token.token;
            if (opt.middleware)
                return next();
            res.json({token: user.token.token});
        }).catch(err=>{
            if (err.name=='MongoError' && err.code==11000 && !opt.middleware)
                return res.status(409).end();
            next(err);
        });
    });
    if (opt.verify)
    {
        app.get('/verify', (req, res, next)=>{
            req.user = null;
            opt.collection.findAndModify({
                query: {
                    'verify.token': req.query.token||'',
                },
                update: {
                    $set: {verified: true},
                    $unset: {verify: ''},
                },
                new: true,
            }).then(user=>{
                req.user = user;
                if (opt.middleware)
                    return next();
                if (!user)
                    return res.status(410).end();
                res.status(200).end();
            }).catch(next);
        });
    }
    if (opt.reset)
    {
        app.post('/reset', (req, res, next)=>{
            req.user = null;
            if (req.body.token)
            {
                return hash(req.body.password).then(hash=>opt.collection.findAndModify({
                    query: {
                        'reset.token': req.body.token,
                    },
                    update: {
                        $set: {password: hash},
                        $unset: {reset: ''},
                    },
                    new: true,
                })).then(user=>{
                    req.user = user;
                    if (opt.middleware)
                        return next();
                    if (!user)
                        return res.status(410).end();
                    res.status(200).end();
                }).catch(next);
            }
            let query = {};
            if (req.body.email)
                query.email = req.body.email;
            else if (req.body.username)
                query.username = req.body.username;
            else
                return res.status(400).end();
            token().then(token=>opt.collection.findAndModify({
                query: query,
                update: {$set: {reset: {
                    token: token,
                    timestamp: new Date(),
                    ua: req.headers['user-agent'],
                }}},
                new: true,
            })).then(user=>{
                req.user = user;
                return user && opt.reset(user);
            }).then(()=>{
                if (opt.middleware)
                    return next();
                res.status(202).end();
            }).catch(next);
        });
        app.get('/reset', (req, res, next)=>{
            req.user = null;
            opt.collection.find({
                'reset.token': req.query.token||'',
            }).then(user=>{
                req.user = user;
                if (opt.middleware)
                    return next();
                if (!user)
                    return res.status(410).end();
                res.json({token: user.reset.token});
            }).catch(next);
        });
    }
    app.get('/logout', (req, res, next)=>{
        if (!req.user)
            return opt.middleware ? next() : res.status(403).end();
        Promise.resolve(+(req.query.all||req.body.all) && token()).then(token=>{
            return token && opt.collection.findAndModify({
                query: {_id: req.user._id},
                update: {$set: {token: {
                    token: token,
                    timestamp: new Date(),
                    ua: req.headers['user-agent'],
                }}},
            });
        }).then(()=>{
            req.session = null;
            if (opt.middleware)
                return next();
            res.status(205).end();
        }).catch(next);
    });
    return app;
};
