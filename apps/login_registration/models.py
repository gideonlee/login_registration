from __future__ import unicode_literals
from django.db import models
from datetime import datetime
import re
import bcrypt

EMAIL_REGEX = re.compile(r'^[\w\.+_-]+@[\w\._-]+\.[\w]*$')

class UserManager(models.Manager):
	def validate(self, **kwargs):
		errors = []
		# Names must be valid 
		if not kwargs['first_name'].isalpha() or len(kwargs['first_name']) < 2:
			errors.append('First Name must be at least 2 characters and contain no numbers.')
		if not kwargs['last_name'].isalpha() or len(kwargs['last_name']) < 2: 
			errors.append('Last Name must be at least 2 characters and contain no numbers.')
		# Email must be valid 
		if not EMAIL_REGEX.match(kwargs['email']):
			errors.append('This is not a valid email.')

		# Birthday must be valid 
		now = datetime.now()
		this_year = int(now.strftime('%Y'))
		if len(kwargs['dob']) < 1:
			errors.append('Birthday cannot be empty.')		
		else: 
			their_birth_year = int(kwargs['dob'][-4:])
			if this_year - their_birth_year < 18: 
				errors.append('You must be 18 or older to attend.')
			else:
				dob = kwargs['dob'][-4:]+'-'+kwargs['dob'][:2]+'-'+kwargs['dob'][3:5]

		# Password must be valid
		if len(kwargs['password']) < 8:
			errors.append('Password must be at least 8 characters long.')
		if kwargs['password'] != kwargs['confirm_password']:
			errors.append('Passwords do not match.')	

		if errors: 
			# Return false and do not add the user
			return (False, errors)
		else: 
			# Encode the password and push this user into the db
			encoded = kwargs['password'].encode()
			hashed = bcrypt.hashpw(encoded, bcrypt.gensalt())

			User.objects.create(first_name=kwargs['first_name'], last_name=kwargs['last_name'], dob=dob, email=kwargs['email'], password=hashed)
			user = User.objects.get(first_name=kwargs['first_name'], last_name=kwargs['last_name'], dob=dob, email=kwargs['email'])
			user_id = str(user.id)
			print '*'*50
			print user.first_name
			print user.last_name
			print user.id
			print user.email
			print user.dob
			print user.created_at
			print user.updated_at
			print '*'*50
			return (True, user_id)

	def login(self, **kwargs):
		errors = []
		try:
			user = User.objects.get(email__iexact=kwargs['email'])

			hashed_pw = user.password.encode() 
			input_pw = kwargs['password'].encode() 

			print hashed_paw
			print input_pw 
			print '*'*50
			print bcrypt.hashpw(kwargs['password'].encode(), user.password.encode())
			# print bcrypt.hashpw(kwargs['email'].encode(), user.password)
			
			# print bcrypt.hashpw(user.password, hashed)

			return user
		except: 
			errors.append('Invalid user/password.')	
			return (False, errors)
		# return user
		# except: 
			# print "It entered down here too."
			# errors.append('Invalid username/password.')
		# return '2'

		# encoded = request.POST['password'].encode()
		# hashed = bcrypt.hashpw(encoded, bcrypt.gensalt())
		# if bcrypt.hashpw(encoded, hashed) == hashed:
		# 	print '*'*50
		# 	print 'IT WORKED'
		# 	print '*'*50
		# else:
		# 	print '*'*50
		# 	print 'IT FAILED'
		# 	print '*'*50
		# return True

class User(models.Model):
	first_name = models.CharField(max_length=45)
	last_name = models.CharField(max_length=45)
	dob = models.DateField()
	email = models.CharField(max_length=255)
	password = models.CharField(max_length=255)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)
	objects = UserManager()
