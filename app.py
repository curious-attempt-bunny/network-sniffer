from flask import Flask
import json

app = Flask(__name__)

@app.route('/')
def index():
  with open('sniffed.json', 'r') as f:
      return json.load(f)