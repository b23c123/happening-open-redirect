from flask import Flask, render_template, request, redirect, jsonify, make_response

app = Flask(__name__)

# ---- 📌 Sample user database ----
users = {
    "admin": "password123"
}

# ---- 📌 Sample shortened URLs for testing ----
shortened_urls = {
    "short1": "https://example.com/dashboard",
    "short2": "https://phishing.com"
}

# --------------------------------------------
# 1️⃣ Login with multiple redirect methods (Vulnerable)
# --------------------------------------------

@app.route('/login_param', methods=['GET', 'POST'])
def login_param():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        next_url = request.args.get('next', '/dashboard')  # 🚨 Vulnerable: No validation
        if username in users and users[username] == password:
            return redirect(next_url)  # 🚨 Unvalidated redirect
        return "Invalid credentials", 401
    return render_template('login.html')

@app.route('/login_referer', methods=['GET', 'POST'])
def login_referer():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        referer = request.headers.get('Referer', '/dashboard')  # 🚨 Vulnerable
        if username in users and users[username] == password:
            return redirect(referer)
        return "Invalid credentials", 401
    return render_template('login.html')

@app.route('/login_cookie', methods=['GET', 'POST'])
def login_cookie():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        next_url = request.cookies.get('next', '/dashboard')  # 🚨 Vulnerable
        if username in users and users[username] == password:
            return redirect(next_url)
        return "Invalid credentials", 401
    return render_template('login.html')

# --------------------------------------------
# 2️⃣ Logout with multiple redirect methods (Vulnerable)
# --------------------------------------------

@app.route('/logout_param')
def logout_param():
    next_url = request.args.get('next', '/home')  # 🚨 No validation
    return redirect(next_url)

@app.route('/logout_referer')
def logout_referer():
    referer = request.headers.get('Referer', '/home')  # 🚨 No validation
    return redirect(referer)

@app.route('/logout_cookie')
def logout_cookie():
    next_url = request.cookies.get('next', '/home')  # 🚨 No validation
    return redirect(next_url)

# --------------------------------------------
# 3️⃣ Open Redirect Vulnerabilities (Unsafe)
# --------------------------------------------

@app.route('/redirect_param')
def redirect_param():
    url = request.args.get('url')  # 🚨 No validation: Allows phishing attacks
    return redirect(url)

@app.route('/redirect_referer')
def redirect_referer():
    referer = request.headers.get('Referer')  # 🚨 No validation: Allows external redirects
    return redirect(referer) if referer else "No Referer Header", 400

@app.route('/redirect_cookie')
def redirect_cookie():
    url = request.cookies.get('url')  # 🚨 No validation: Unsafe redirect
    return redirect(url) if url else "No URL in Cookie", 400

@app.route('/redirect_js')
def redirect_js():
    return '''
        <script>
            var url = new URLSearchParams(window.location.search).get('url');
            if (url) window.location = url;  // 🚨 JavaScript-based redirect vulnerability
        </script>
    '''

# --------------------------------------------
# 4️⃣ Short URL Redirect (Phishing Vulnerability)
# --------------------------------------------

@app.route('/short/<code>')
def short_url_redirect(code):
    url = shortened_urls.get(code)  # 🚨 Redirects to potentially malicious links
    if url:
        return redirect(url)
    return "Invalid short URL", 404

# --------------------------------------------
# 5️⃣ Other Pages
# --------------------------------------------

@app.route('/dashboard')
def dashboard():
    return "<h1>Welcome to your dashboard</h1>"

@app.route('/home')
def home():
    return "<h1>Home Page</h1>"

@app.route('/welcome')
def welcome():
    return "<h1>Welcome to the platform</h1>"

@app.route('/profile')
def profile():
    return "<h1>Your Profile</h1>"

# --------------------------------------------
# 6️⃣ API Redirect (Vulnerable)
# --------------------------------------------

@app.route('/api/redirect', methods=['POST'])
def api_redirect():
    data = request.get_json()
    url = data.get('url')  # 🚨 No validation: Can be used to redirect users to phishing sites
    if url:
        return jsonify({"status": "success", "redirect_url": url}), 200
    return jsonify({"status": "error", "message": "No URL provided"}), 400

# --------------------------------------------
# 📌 Home Page: Show All Vulnerabilities
# --------------------------------------------

@app.route('/')
def index():
    return '''
        <h1>⚠️ Security Testing Website ⚠️</h1>
        <p>This site demonstrates multiple security vulnerabilities.</p>
        
        <h2>🚨 Open Redirects</h2>
        <ul>
            <li><a href="/redirect_param?url=https://evil.com">Redirect via URL Parameter</a></li>
            <li><a href="/redirect_referer">Redirect via Referer Header</a></li>
            <li><a href="/redirect_cookie">Redirect via Cookie</a></li>
            <li><a href="/redirect_js?url=https://evil.com">Redirect via JavaScript</a></li>
        </ul>

        <h2>🔑 Insecure Logins</h2>
        <ul>
            <li><a href="/login_param?next=https://evil.com">Login Redirect via Parameter</a></li>
            <li><a href="/login_referer">Login Redirect via Referer</a></li>
            <li><a href="/login_cookie">Login Redirect via Cookie</a></li>
        </ul>

        <h2>🔄 Unsafe Logout Redirects</h2>
        <ul>
            <li><a href="/logout_param?next=https://evil.com">Logout Redirect via Parameter</a></li>
            <li><a href="/logout_referer">Logout Redirect via Referer</a></li>
            <li><a href="/logout_cookie">Logout Redirect via Cookie</a></li>
        </ul>

        <h2>📌 Short URL Phishing</h2>
        <ul>
            <li><a href="/short/short2">Phishing via Shortened URL</a></li>
        </ul>

        <h2>📊 Normal Pages</h2>
        <ul>
            <li><a href="/dashboard">Dashboard</a></li>
            <li><a href="/home">Home</a></li>
            <li><a href="/welcome">Welcome</a></li>
            <li><a href="/profile">Profile</a></li>
        </ul>

        <p>⚠️ This site is for educational purposes only. Do not use in production. ⚠️</p>
    '''

# --------------------------------------------
# Run the application
# --------------------------------------------

if __name__ == '__main__':
    app.run(debug=True)
