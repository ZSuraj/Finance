import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify
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

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

time = datetime.now()

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
    try:
        id = session["user_id"]

        # Table
        stocks = db.execute("SELECT share_name, symbol, SUM(no_of_shares) AS shares FROM transactions GROUP BY share_name HAVING SUM(no_of_shares) > 0")
        stock = {}
        total = {}

        cash = db.execute("SELECT cash FROM users WHERE id = ?", id)
        user_cash = cash[0]["cash"]

        for s in stocks:
            stock[s["symbol"]] = lookup(s["symbol"])["price"]
            total[s["symbol"]] = lookup(s["symbol"])["price"] * s["shares"]

        GrandTotal = sum(total.values()) + user_cash

        # Table to template
        return render_template("index.html", stocks=stocks, usd=usd, stock=stock, cash=user_cash, total=total, GrandTotal=GrandTotal)

    except:
        return redirect("/register")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # POST request
    if request.method == "POST":

        # Getting input
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        stock = lookup(symbol)

        if not shares.isdigit():
            return apology("Could not buy partial shares")

        shares = int(shares)

        # Validate input
        if not symbol:
            return apology("Provide Symbol")
        elif stock == None:
            return apology("Invalid Symbol")
        elif shares < 1:
            return apology("Invalid number of shares")

        foreign_id = session["user_id"]

        # Current cash
        cash = db.execute("SELECT cash FROM users WHERE id = ?", foreign_id)
        user_cash = cash[0]["cash"]

        price = shares * stock["price"]

        # Purchasing power
        if user_cash < price:
            return apology("Cash not enough.")

        # Insert data
        db.execute("INSERT INTO transactions (share_name, symbol, no_of_shares, time, price, foreign_id, share_price, type) VALUES(?, ?, ?, ?, ?, ?, ?, ?)", stock["name"], stock["symbol"], shares, time, price, foreign_id, stock["price"], "buy")

        # Update cash
        user_cash -= price

        db.execute("UPDATE users SET cash = ? WHERE id = ?", user_cash, foreign_id)

        flash("Bought!")

        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # User id
    id = session["user_id"]

    # Data from database
    stocks = db.execute("SELECT * FROM transactions WHERE foreign_id = ?", id)

    return render_template("history.html", stocks=stocks)


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
    return redirect("/login")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # POST request
    if request.method == "POST":
        quote = request.form.get("symbol")
        quoted = lookup(quote)

        if not quote:
            return apology("Provide a symbol")
        if not quoted:
            return apology("Symbol Not Found!")
        else:
            return render_template("quoted.html", quote=quoted)

    # GET request
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Getting the user's input
        name = request.form.get("username")
        password = request.form.get("password")
        confirm_password = request.form.get("confirmation")

        existing_username = db.execute("SELECT username FROM users")

        list = []
        for i in existing_username:
            l = i["username"]
            list.append(l)

        # Checking everything was written
        if not name:
            return apology("Provide name")
        elif not password:
            return apology("Provide password")
        elif not confirm_password:
            return apology("Provide Confirmation")

        # Password equal to confirm_password
        elif password != confirm_password:
            return apology("PASSWORDS NOT MATCHING!")

        # Ensure username already exists
        elif name in list:
            return apology("Username already exists")

        # Add new user to table
        else:
            hash = generate_password_hash(password)
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", name, hash)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", name)

        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    id = session["user_id"]

    # POST method
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        stock = lookup(symbol)

        owned_shares = db.execute("SELECT no_of_shares FROM transactions WHERE symbol = ? AND foreign_id = ? GROUP BY symbol", symbol, id)
        owned_shares = owned_shares[0]["no_of_shares"]

        # Check
        if not symbol:
            return apology("Stock Not Found")
        elif shares < 0:
            return apology("Shares Not Available")
        elif shares > owned_shares:
            return apology("Not enough shares")

        # Update cash
        cash = db.execute("SELECT cash FROM users WHERE id = ?", id)[0]["cash"]

        price = shares * stock["price"]

        cash += price

        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, id)

        # Insert data into table
        db.execute("INSERT INTO transactions (share_name, symbol, no_of_shares, time, price, foreign_id, share_price, type) VALUES(?, ?, ?, ?, ?, ?, ?, ?)", stock["name"], stock["symbol"], -shares, time, price, id, stock["price"], "sell")

        # flash("Sold!")

        return redirect("/")

    # GET method
    else:
        stocks = db.execute("SELECT symbol FROM transactions WHERE foreign_id = ? GROUP BY symbol", id)
        return render_template("sell.html", stocks=stocks)


@app.route("/Reset", methods=["GET", "POST"])
def reset():

    # POST method
    if request.method == "POST":

        username = request.form.get("username")

        # Username from database
        username_check = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Username check
        if not username_check:
            return apology("Username does not exist.")

        username_check = username_check[0]["username"]

        if username_check == username:
            return render_template("resetpassword.html")
        else:
            return apology("Username does not exist.")

    # GET method
    else:
        return render_template("resetrequest.html")


@app.route("/Reset_password", methods=["POST"])
def reset_password():

    # Obtain new password from user
    password = request.form.get("password")
    confirmation = request.form.get("confirmation")

    # Check everything was written
    if not password:
        return apology("Please provide password.")

    if not confirmation:
        return apology("Please provide password.")

    elif password != confirmation:
        return apology("Passwords Does Not Match.")

    # Updating password
    else:
        hash = generate_password_hash(password)
        db.execute("UPDATE users SET hash = ?", hash)

    flash("Reset passwords successful")

    return redirect("/login")


@app.route("/addcash", methods=["GET", "POST"])
@login_required
def cash():

    # POST method
    if request.method == "POST":

        # User id
        id = session["user_id"]

        # Existing cash amount
        old_cash = db.execute("SELECT cash FROM users WHERE id = ?", id)[0]["cash"]

        # Cash from user using POST
        add_cash = float(request.form.get("addcash"))

        # Existing cash and Additional cash
        cash = old_cash + add_cash

        # Updating the new amount
        db.execute("UPDATE users SET cash = ?", cash)

        # Return to main page
        return redirect("/")

    # GET method
    else:
        return render_template("addcash.html")