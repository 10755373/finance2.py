import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Ensure environment variable is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # vraag alle symbols van de gebruiker op
    portfolio = db.execute("SELECT shares, symbol FROM portfolio WHERE id=:id;", id=session["user_id"])
    grand_total = usd(0)

    if portfolio != []:
        stocks = []
        current_cash = usd(db.execute("SELECT cash FROM users WHERE id= id;", id=session["user_id"]))

        for symbol in portfolio:
            symbol_data = lookup(symbol["symbol"])
            stock_shares = db.execute("SELECT SUM(quantity) FROM transactions WHERE id=:id AND symbol = :symbol;",
                                      id=session["user_id"], symbol=symbol_data["symbol"])
            if stock_shares[0]["SUM(quantity)"] == 0:
                continue
            else:
                stock_info = {}
                stock_info["name"] = symbol_data["name"]
                stock_info["symbol"] = symbol_data["symbol"]
                stock_info["price"] = usd(symbol_data["price"])
                stock_info["shares"] = stock_shares[0]["SUM(quantity)"]
                stock_info["total"] = usd(stock_info["shares"] * stock_info["price"])
                stocks.append(stock_info)
        for i in range(len(stocks)):
            grand_total += usd(stocks[i]["total"])
            grand_total += usd(current_cash[0]["cash"])

        for i in range(len(stocks)):
            stocks[i]["price"] = usd(stocks[i]["price"])
            stocks[i]["total"] = usd(stocks[i]["total"])
    else:
        current_cash = db.execute("SELECT cash FROM users WHERE id=:user_id;", user_id=session["user_id"])
        return render_template("index.html", current_cash=usd(current_cash[0]["cash"]), grand_total=usd(current_cash[0]["cash"]))
    # voeg extra geld toe wanneer user dat verlangd
    if request.method == "POST":
        if request.form.get("add_cash").isint() == False:
            return apology("Please give valid amount")
        elif request.form.get("add_cash").isfloat() == False:
            return apology("Please give valid amount")
        else:
            db.execute("UPDATE users SET cash=:cash WHERE id=:id", cash=current_cash +\
                       usd(request.form.get("add_cash")), id=session["user_id"])
            current_cash = current_cash + usd(request.form.get("add_cash"))
        # laat nieuwe geldbalans en totale waarde zien
        return render_template("index.html", stocks=stocks, current_cash=usd(current_cash[0]["cash"]), grand_total=usd(grand_total))
    # zo niet
    else:
        if request.method == "GET":
            return render_template("index.html", stocks=stocks, current_cash=usd(current_cash[0]["cash"]), grand_total=usd(grand_total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    # geldige invoer
    if request.method == "POST":
        # check voor geldige invoer
        aandeel = lookup(request.form.get("symbol"))
        if not aandeel:
            return apology("Invalid input, please try again", 400)
        # check voor geldige invoer
        # check for valid input
        if request.form.get("shares").isdigit() == False:
            return apology("invalid number of shares")

        # get number of how many shares to buy
        shares = float(request.form.get("shares"))
        if shares < 0:
            return apology("invalid number of shares")


        # hoeveelheid geld van user
        geld = usd(db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"]))
        current_cash = usd(geld[0]["cash"])
        # ga na of het voldoende geld is
        if current_cash < usd(shares * aandeel["price"]):
            return apology("Unfortunately, you don't have enough money", 400)
        else:
            # voer transactie in
            db.execute("INSERT INTO transactions (id, symbol, shares, price, total, date_time) VALUES (:id, :symbol, :shares, :price, :total, DATETIME();",
                       id=session["user_id"], symbol=aandeel["symbol"], shares=shares, price=usd(aandeel["price"]), total=usd(aandeel["price"] * shares))
            # update de cash van de user
            db.execute("UPDATE users SET cash = cash - :purchase WHERE id:id;", \
                       purchase=usd(aandeel["price"] * shares), id=session["user_id"])
            # Select user shares of that symbol
            user_shares = db.execute("SELECT shares FROM portfolio \
                           WHERE id=:id AND symbol=:symbol", \
                           id=session["user_id"], symbol=aandeel["symbol"])
            # ingeval aankoop aandeel dat user nog niet bezit
            if not user_shares:
                db.execute("INSERT INTO portfolio (id, symbol, shares, price, total) \
                        VALUES(id:, :symbol, :shares, :price, :total)", \
                        symbol=aandeel["symbol"], shares=shares, price=usd(aandeel["price"]), \
                        total=usd(shares * aandeel["price"]), id=session["user_id"])
            # ingeval user al aandelen van dat bedrijf bezit
            else:
                shares_total = (user_shares[0]["shares"] + shares)
                db.execute("UPDATE portfolio SET shares=:shares \
                        WHERE id=:id AND symbol=:symbol", \
                        shares=shares_total, id=session["user_id"], \
                        symbol=aandeel["symbol"])
        return redirect("/", 400)
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions."""
    transactions = db.execute(\
                              "SELECT id, symbol, shares, price, total, date_time FROM transactions WHERE id=:id", id=session["user_id"])
    # zorg ervoor dat alles in dollars staat
    for transaction in transactions:
        transactions["price"] = usd(transactions["price"])
    # ga na of transactie buy/sell betrof
    for i in range(len(transactions)):
        if transactions[i]["price"] > 0:
            transactions[i]["Action"] = 'Buy'
        elif transactions[i]["price"] < 0:
            transactions[i]["price"] = 'Sell'
    return render_template("transactions.html", transactions=transactions)


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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

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
    # redirect user to home page
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    # ga correctheid input na
    if request.method == "POST":
        quote = lookup(request.form.get("symbol"))
        if not quote:
            return apology("Invalid Symbol", 400)
        else:
            quote["price"] = usd(quote["price"])
            return render_template("quote.html", quote=quote)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # zorg voor invoer username
        if not request.form.get("username"):
            return apology("Please insert username")
        # zorg voor invoer password
        elif not request.form.get("password"):
            return apology("Please insert password")
        # zorg voor invoer passwordcheck
        elif not request.form.get("confirmation"):
            return apology("Please insert passwordcheck")
        # controle van invoer
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("Please make sure password is the same")
        password = request.form.get("password")
        # ga uniekheid na
        result = db.execute("INSERT INTO users (username, hash) VALUES(:username, :hash)", \
                            username=request.form.get("username"), hash=generate_password_hash(password))
        if not result:
            return apology("Username already exists, please insert unique one")
        # plaats username in database
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))
        # onthoud ingelogde user
        session["user_id"] = rows[0]["id"]
        # begeleid user naar homepage
        return redirect("/")
    # ingeval user op andere manier bij de pagina kwam
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # geldige invoer
    if request.method == "POST":
        try:
            symbol = lookup(request.form.get("symbol"))
            shares = int(request.form.get("shares"))
        except:
            return apology("Invalid input, please try again")
        # vraag om geldige invoer
        if not shares or symbol:
            return apology("Invalid input, please try again")
        # vraag om positieve invoer
        if shares <= 0:
            return apology("Shares must be a positive integer")
        else:
            stocks_possession = db.execute("SELECT SUM(quantity) FROM portfolio WHERE id=:id AND symbol=:symbol;",
                                           id=session["users_id"], shares=symbol["symbol"])
            # ga na of user de stocks daadwerkelijk bezit
            if not stocks_possession[0]["SUM(quantity)"]:
                return apology("You don't have any of these stocks")
            # ingeval user meer wilt verkopen dan dat 'ie bezit
            if shares > stocks_possession[0]["SUM(quantity)"]:
                return apology("You don't have that many stocks")
            # maak transactie waarbij verkoop van de aandelen een negatieve transactie is
            db.execute("INSERT INTO transactions (id, symbol, shares, price, total, date_time) VALUES (:id, :symbol, :shares, :price, :total, DATETIME();",
                       id=session["user_id"], symbol=symbol["symbol"], shares=(-1 * shares), price=(-1 * symbol["price"]), total=(-1 * symbol["price"] * shares))
            # update de cash van de user
            db.execute("UPDATE users SET cash=cash + :total WHERE id:id;", total=(symbol["price"] * shares), id=session["user_id"])
        return redirect("/")
    else:
        return render_template("sell.html")


def errorhandler(e):
    """Handle error"""
    return apology(e.name, e.code)


@app.route("/account", methods=["GET", "POST"])
def account():
    """change users password"""
    if request.method == "POST":

        accounts = db.execute("SELECT * FROM users WHERE id=:id;", id=session["user_id"])
        # check voor geldige invoer huidig wachtwoord
        if not request.form.get("password"):
            return apology("Please insert current password")
        # vraag om nieuwe wachtwoord
        if not request.form.get("new-password"):
            return apology("Please insert a new password")
        # zorg voor invoer passwordcheck
        if not request.form.get("password-confirm"):
            return apology("Please insert newpasswordcheck")
        # controle van invoer
        if request.form.get("newpassword") != request.form.get("newpasswordcheck"):
            return apology("Please make sure password is the same")
        newpassword = request.form.get("newpassword")
        db.execute("UPDATE users SET hash=hash;", hash=generate_password_hash(newpassword))
        return redirect("/")
    else:
        return render_template("account.html")


# listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
