from voic import db, models


if __name__ == '__main__':
    db.create_all()

    engineer_role = models.Role(title='engineer')
    db.session.add(engineer_role)
    hr_role = models.Role(title='hr')
    db.session.add(hr_role)

    admin_user = models.User(username='admin', password='admin',email='admin@admin.com')
    admin_user.roles.append(hr_role)
    db.session.add(admin_user)

    bob_user = models.User(username='bob', password='bob', email='bob@bob.com')
    bob_user.roles.append(hr_role)
    db.session.add(bob_user)

    hayden_user = models.User(username='hayden', password='hayden', email='hayden@hayden.com')
    hayden_user.roles.append(engineer_role)
    db.session.add(hayden_user)

    austin_user = models.User(username='austin', password='austin', email='austin@austin.com')
    austin_user.roles.append(engineer_role)
    db.session.add(austin_user)

    bill_user = models.User(username='bill', password='bill', email='bill@bill.com')
    bill_user.roles.append(engineer_role)
    db.session.add(bill_user)

    design_document = models.Document(creator_id=1, title='Design plan', content='Content')
    admin_user.documents.append(design_document)
    hayden_user.documents.append(design_document)
    engineer_role.documents.append(design_document)
    db.session.add(design_document)

    db.session.commit()
