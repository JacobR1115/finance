import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Function to jinja
app.jinja_env.globals.update(lookup=lookup)
app.jinja_env.globals.update(round=round)
app.jinja_env.globals.update(usd=usd)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    stocks = db.execute("SELECT * FROM owned_stock WHERE userID = ?", session["user_id"])
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    net_cash = cash[0]['cash']
    for stock in stocks:
        symbol = lookup(stock['symbol'])
        net_cash += (symbol["price"] * (stock['shares']))
    net_cash = round(net_cash)
    return render_template("index.html", stocks=stocks, cash=cash[0]['cash'], net_cash=net_cash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # User submits the form
    if request.method == "POST":
        if lookup(request.form.get("symbol")) == None:
            return apology("symbol does not exist", 403)
        elif int(request.form.get("shares")) < 1:
            return apology("include a number of shares", 403)
        # User input an existing symbol and non-negative, non-zero number of shares
        else:
            symbol = request.form.get("symbol")
            shares = int(request.form.get("shares"))
            cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
            quote = lookup(request.form.get("symbol"))
            time = datetime.now()
            date_time = time.strftime("%m/%d/%Y %H:%M:%S")

            # If user does not have enough cash
            if (quote["price"] * shares) > cash[0]['cash']:
                return apology("not enough cash to purchase", 403)

            # If user does have enough cash
            else:
                # Records the purchase if stock not owned
                if db.execute("SELECT * FROM owned_stock WHERE symbol = ? AND userID = ?" , symbol.upper(), session["user_id"]):
                    current_shares = db.execute("SELECT shares FROM owned_stock WHERE symbol = ? AND userID = ?", symbol.upper(), session["user_id"])
                    new_shares = shares + current_shares[0]['shares']
                    db.execute("UPDATE owned_stock SET shares = ? WHERE symbol = ? AND userID = ?", new_shares, symbol.upper(), session["user_id"])
                else:
                    db.execute("INSERT INTO owned_stock (symbol, shares, userID) VALUES(?, ?, ?)", symbol.upper(), shares, session["user_id"])
                    # TODO: Record purchase of stock owned
                    # TODO: subtract the funds from the user's account
                db.execute("INSERT INTO transactions (symbol, shares, type, price, time, userID) VALUES(?, ?, ?, ?, ?, ?)", symbol.upper(), shares, "Bought", quote["price"] * shares, date_time, session["user_id"])
                cash[0]['cash'] = cash[0]['cash'] - (quote["price"] * shares)
                db.execute("UPDATE users SET cash = ? WHERE id = ?", cash[0]['cash'], session["user_id"])

                return redirect("/")

    # User accesses the page via a link
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute("SELECT * FROM transactions WHERE userID = ?", session["user_id"])
    return render_template("history.html", history=history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # User submits a quote
    if request.method == "POST":

        # Symbol does not exist
        if lookup(request.form.get("symbol")) == None:
            return apology("symbol does not exist", 403)


        quote = lookup(request.form.get("symbol"))


        return render_template("quoted.html", name=quote["name"], price=(quote["price"]))

    # User reached route via GET (by clicking a link or via redirect)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # User did not input a username
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # User did not input password or confirmation password
        elif not request.form.get("password") and not request.form.get("confirmation"):
            return apology("must provide password and confirm passoword", 403)

        # User's password and confirmation do not match
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("password and confirmation password must match", 403)

        username = request.form.get("username")
        password = generate_password_hash(request.form.get("password"))

        # Check if username already exists
        if db.execute("SELECT * FROM users WHERE username = ?", username):
            return apology("username already exists", 403)

        # Insert username and passowrd into users
        rows = db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, password)

        return redirect("/login")

    # User reached route via GET (by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        if lookup(request.form.get("symbol")) == None:
            return apology("symbol does not exist", 403)
        elif int(request.form.get("shares")) < 1:
            return apology("include a number of shares to sell", 403)
        # User input an existing symbol and non-negative, non-zero number of shares
        else:
            symbol = request.form.get("symbol")
            shares = int(request.form.get("shares"))
            cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
            quote = lookup(request.form.get("symbol"))
            time = datetime.now()
            date_time = time.strftime("%m/%d/%Y %H:%M:%S")
            if not db.execute("SELECT shares FROM owned_stock WHERE symbol = ? AND userID = ?", symbol.upper(), session["user_id"]):
                return apology("you do not own this stock", 403)

            current_shares = db.execute("SELECT shares FROM owned_stock WHERE symbol = ? AND userID = ?", symbol.upper(), session["user_id"])

            # User does not have enough shares
            if shares > current_shares[0]['shares']:
                return apology("can't sell more shares then owned", 403)

            # If user does have enough cash
            else:
                # Records the sale if selling some shares of stock
                if shares < current_shares[0]['shares']:
                    new_shares = current_shares[0]['shares'] - shares
                    db.execute("UPDATE owned_stock SET shares = ? WHERE symbol = ? AND userID = ?", new_shares, symbol.upper(), session["user_id"])
                # Records the sale if selling all shares of stock
                else:
                    db.execute("DELETE FROM owned_stock WHERE symbol = ? AND userID = ?", symbol.upper(), session["user_id"])
                # Records transaction
                db.execute("INSERT INTO transactions (symbol, shares, type, price, time, userID) VALUES(?, ?, ?, ?, ?, ?)", symbol.upper(), shares, "Sold", quote["price"] * shares, date_time, session["user_id"])
                # TODO: add cash to users = price * shares sold
                cash[0]['cash'] = cash[0]['cash'] + (quote["price"] * shares)
                db.execute("UPDATE users SET cash = ? WHERE id = ?", cash[0]['cash'], session["user_id"])

                return redirect("/")
    else:
        stocks = db.execute("SELECT symbol FROM owned_stock WHERE userID = ?", session["user_id"])
        return render_template("sell.html", stocks=stocks)

@app.route("/changePassword", methods=["GET", "POST"])
@login_required
def changePassword():
    """Change user password"""
    if request.method == "POST":
        # User did not input password or confirmation password
        if not request.form.get("password") and not request.form.get("confirmation"):
            return apology("must provide password and confirm passoword", 403)
        # User's password and confirmation do not match
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("password and confirmation password must match", 403)
        password = generate_password_hash(request.form.get("password"))
        db.execute("UPDATE users SET hash = ? WHERE id = ?", password, session["user_id"])

        return redirect("/")

    else:
        return render_template("changePassword.html")