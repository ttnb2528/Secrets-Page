import express from "express";
import bodyParser from "body-parser";
import ejs from "ejs";
import pg from "pg";
// Add crypto library to pgAdmin to use crypt in queries

const app = express();
const port = 3000;


const db = new pg.Client({
    user: 'postgres',
    host: 'localhost',
    database: 'Secrets',
    password: 'Tan281201!',
    port: 5432
})

app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true}));
// set the default view engine to ejs, like find file dot ejs and render them
app.set('view engine', 'ejs');

db.connect();

app.get('/', (req, res) => {
    res.render('home')
})

app.get('/register', (req, res) => {
    res.render('register')
})

app.get('/login', (req, res) => {
    res.render('login')
})

app.post('/register',async  (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    try {
        await db.query("INSERT INTO users (username, password) VALUES ($1, crypt($2, gen_salt('md5')));",
        [username, password]);

        res.render('secrets');
    } catch (err) {
        res.render('register', {
            error: "Something went wrong, let try again!"
        });

        console.log(err);
    }
});

app.post('/login', async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    
    try {
        const result = await db.query('SELECT * FROM users WHERE username = $1 AND password = crypt($2, password);',
        [username, password]);

        if (result.rows.length > 0) {
            res.render('secrets');
        } else {
            res.render('login', {
                error: "Username or password is incorrect!"
            });
        }
    } catch (err) {
        res.render('login', {
            error: "Username or password is incorrect!"
        });
    }
})

app.listen(port, () => {
    console.log(`Server started on port ${port}`);
})