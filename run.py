from app import db, create_app

# db.create_all()
application = create_app()
with application.app_context():
    db.create_all()

if __name__ == "__main__":
    print('http://127.0.0.1:5345/docs')
    application.run(host='0.0.0.0', port=5345)
