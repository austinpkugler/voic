import dotenv

from voic import app


if __name__ == '__main__':
    dotenv.load_dotenv()
    app.run(debug=True)
