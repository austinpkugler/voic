from voic import db, models


if __name__ == '__main__':
    db.create_all()
    role_titles = ['engineer', 'designer', 'custodian', 'valet', 'admin', 'ceo']
    for role_title in role_titles:
        role = models.Role(title=role_title)
        db.session.add(role)
    db.session.commit()
