# auth_website.py - Complete Flask app for Spotify/YouTube Music authentication
from flask import Flask, render_template, request, redirect, session, jsonify, url_for
import os
import json
import requests
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
import spotipy
from spotipy.oauth2 import SpotifyOAuth
from ytmusicapi import YTMusic
import tempfile
import pickle

from dotenv import load_dotenv

load_dotenv()
# Enable insecure transport for development (DO NOT USE IN PRODUCTION)
if os.getenv('FLASK_ENV') == 'development':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-change-this-in-production')

# Your app credentials (set these as environment variables!)
SPOTIFY_CLIENT_ID = os.getenv('SPOTIFY_CLIENT_ID', 'your_spotify_client_id')
SPOTIFY_CLIENT_SECRET = os.getenv('SPOTIFY_CLIENT_SECRET', 'your_spotify_client_secret')
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID', 'your_google_client_id')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET', 'your_google_client_secret')

# OAuth Configuration
BASE_URL = os.getenv('BASE_URL', 'https://your-auth-website.com')
SPOTIFY_REDIRECT_URI = f"{BASE_URL}/callback/spotify"
GOOGLE_REDIRECT_URI = f"{BASE_URL}/callback/google"

SPOTIFY_SCOPES = "playlist-read-private user-library-read playlist-modify-public playlist-modify-private"
GOOGLE_SCOPES = ['https://www.googleapis.com/auth/youtube']

@app.route('/')
def index():
    """Main page with authentication options."""
    return render_template('index.html')

@app.route('/auth/spotify')
def spotify_auth():
    """Initiate Spotify OAuth flow."""
    try:
        auth_manager = SpotifyOAuth(
            client_id=SPOTIFY_CLIENT_ID,
            client_secret=SPOTIFY_CLIENT_SECRET,
            redirect_uri=SPOTIFY_REDIRECT_URI,
            scope=SPOTIFY_SCOPES,
            show_dialog=True  # Always show dialog for better UX
        )
        
        auth_url = auth_manager.get_authorize_url()
        return redirect(auth_url)
    except Exception as e:
        return render_template('error.html', 
                             error=f"Failed to initiate Spotify authentication: {str(e)}")

@app.route('/callback/spotify')
def spotify_callback():
    """Handle Spotify OAuth callback."""
    code = request.args.get('code')
    error = request.args.get('error')
    
    if error:
        return render_template('error.html', 
                             error=f"Spotify authentication denied: {error}")
    
    if not code:
        return render_template('error.html', 
                             error="No authorization code received from Spotify")
    
    try:
        auth_manager = SpotifyOAuth(
            client_id=SPOTIFY_CLIENT_ID,
            client_secret=SPOTIFY_CLIENT_SECRET,
            redirect_uri=SPOTIFY_REDIRECT_URI,
            scope=SPOTIFY_SCOPES
        )
        
        token_info = auth_manager.get_access_token(code)
        
        # Test the token to make sure it works
        sp = spotipy.Spotify(auth=token_info['access_token'])
        user_info = sp.current_user()
        
        session['spotify_token'] = token_info
        session['spotify_user'] = user_info['display_name'] or user_info['id']
        
        return redirect(url_for('success', platform='spotify'))
        
    except Exception as e:
        return render_template('error.html', 
                             error=f"Error getting Spotify token: {str(e)}")

@app.route('/auth/youtube')
def youtube_auth():
    """Initiate YouTube/Google OAuth flow."""
    try:
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "redirect_uris": [GOOGLE_REDIRECT_URI],
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token"
                }
            },
            scopes=GOOGLE_SCOPES
        )
        flow.redirect_uri = GOOGLE_REDIRECT_URI
        
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'  # Force consent screen to get refresh token
        )
        
        session['oauth_state'] = state
        return redirect(authorization_url)
        
    except Exception as e:
        return render_template('error.html', 
                             error=f"Failed to initiate YouTube Music authentication: {str(e)}")

@app.route('/callback/google')
def google_callback():
    """Handle Google/YouTube OAuth callback."""
    error = request.args.get('error')
    if error:
        return render_template('error.html', 
                             error=f"YouTube Music authentication denied: {error}")
    
    state = request.args.get('state')
    if not state or state != session.get('oauth_state'):
        return render_template('error.html', 
                             error="Invalid state parameter")
    
    try:
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "redirect_uris": [GOOGLE_REDIRECT_URI],
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token"
                }
            },
            scopes=GOOGLE_SCOPES,
            state=state
        )
        flow.redirect_uri = GOOGLE_REDIRECT_URI
        
        # Get the authorization response
        authorization_response = request.url
        flow.fetch_token(authorization_response=authorization_response)
        
        credentials = flow.credentials
        
        # Create YTMusic auth headers
        # We'll use a temporary approach to get the headers
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            temp_file.write(json.dumps({
                'access_token': credentials.token,
                'refresh_token': credentials.refresh_token,
                'token_uri': credentials.token_uri,
                'client_id': credentials.client_id,
                'client_secret': credentials.client_secret,
                'scopes': credentials.scopes
            }))
            temp_path = temp_file.name
        
        try:
            # Initialize YTMusic to get the proper headers format
            ytmusic = YTMusic()
            # The actual headers we need for the CLI tool
            auth_headers = {
                'Authorization': f'Bearer {credentials.token}',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            # Store in session
            session['youtube_credentials'] = {
                'access_token': credentials.token,
                'refresh_token': credentials.refresh_token,
                'token_uri': credentials.token_uri,
                'client_id': credentials.client_id,
                'client_secret': credentials.client_secret,
                'scopes': list(credentials.scopes) if credentials.scopes else []
            }
            session['youtube_headers'] = auth_headers
            
        finally:
            # Clean up temp file
            if os.path.exists(temp_path):
                os.unlink(temp_path)
        
        return redirect(url_for('success', platform='youtube'))
        
    except Exception as e:
        return render_template('error.html', 
                             error=f"Error processing YouTube Music authentication: {str(e)}")

# Updated success route in auth_website.py
@app.route('/success')
def success():
    """Success page showing simplified tokens."""
    platform = request.args.get('platform')
    
    if platform == 'spotify':
        token_data = session.get('spotify_token')
        if not token_data:
            return redirect(url_for('index'))
        
        # Extract just the access token and expiry info
        access_token = token_data.get('access_token', '')
        expires_at = token_data.get('expires_at')
        
        # Calculate human-readable expiry
        expiry_info = None
        if expires_at:
            import datetime
            expiry_time = datetime.datetime.fromtimestamp(expires_at)
            expiry_info = expiry_time.strftime('%Y-%m-%d %H:%M:%S')
        
        return render_template('success.html', 
                             platform='Spotify',
                             token=access_token,
                             expiry=expiry_info,
                             user=session.get('spotify_user', 'Unknown'),
                             token_type='spotify')
    
    elif platform == 'youtube':
        credentials = session.get('youtube_credentials')
        if not credentials:
            return redirect(url_for('index'))
        
        # Extract just the access token
        access_token = credentials.get('access_token', '')
        
        return render_template('success.html', 
                             platform='YouTube Music',
                             token=access_token,
                             expiry=None,  # YouTube tokens don't show expiry in same format
                             user='YouTube Music User',
                             token_type='youtube')
    
    else:
        return redirect(url_for('index'))
    
@app.route('/api/tokens')
def get_tokens():
    """API endpoint to get tokens as JSON."""
    tokens = {}
    
    if 'spotify_token' in session:
        tokens['spotify'] = session['spotify_token']
    
    if 'youtube_credentials' in session and 'youtube_headers' in session:
        tokens['youtube'] = {
            'Authorization': session['youtube_headers']['Authorization'],
            'User-Agent': session['youtube_headers']['User-Agent'],
            'credentials': session['youtube_credentials']
        }
    
    return jsonify(tokens)

@app.route('/clear')
def clear_session():
    """Clear all session data."""
    session.clear()
    return redirect(url_for('index'))

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error="Internal server error"), 500

if __name__ == '__main__':
    # Check for required environment variables
    required_vars = ['SPOTIFY_CLIENT_ID', 'SPOTIFY_CLIENT_SECRET', 'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET']
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        print(f"❌ Missing required environment variables: {', '.join(missing_vars)}")
        print("Please set these environment variables before running the application.")
        exit(1)
    
    # Development vs Production settings
    is_development = os.getenv('FLASK_ENV') == 'development'
    
    if is_development:
        print("🚨 DEVELOPMENT MODE: Running with HTTP (insecure transport enabled)")
        print("⚠️  DO NOT use this configuration in production!")
        print("🔒 For production, use HTTPS with a proper SSL certificate")
        app.run(debug=True, host='0.0.0.0', port=5000)
    else:
        print("🔒 PRODUCTION MODE: Requires HTTPS")
        print("Make sure your server is configured with SSL/TLS certificates")
        app.run(debug=False, host='0.0.0.0', port=5000)