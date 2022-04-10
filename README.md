# VOiC
A project by Austin Kugler and Hayden Carroll for CS-360.

# Description
While almost all of the documents we write, read, share, act on, process or archive are digital, their management remains archaic. In VOiC, we make provisions to support decision workflows, virtual office and provenance and privacy based on role-based authorization. The system is based upon a recently proposed model for document management in virtual offices.

# Setup
Run the following commands:
```
git clone https://github.com/austinpkugler/voic.git
pip install -r requirements.txt
```
Now, create a file called `.env` at the project's root directory. The file should be in the following format:
```
FLASK_SECRET_KEY="yoursecretkey"
```
Generate the database:
```
python create_db.py
```
You can now run the webserver locally:
```
python run.py
```