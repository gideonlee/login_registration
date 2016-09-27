from django.shortcuts import render, redirect
from .models import UserManager, User
from django.contrib import messages

# Registration/Login Page
def index(request):
	# User.objects.all().delete()
	return render(request, 'login_registration/index.html')

# Onced logged in, use session to get a hold of the user
def summary(request, id):
	user = User.objects.get(id=id)
	request.session['user'] = {
		'first_name': user.first_name,
		'last_name': user.last_name,
		'email': user.email,
		'dob': str(user.dob)
	}
	return render(request, 'login_registration/summary.html')

# Registration will use the validate UserManager method and check if the inputs are valid. 
def register(request):
	result = User.objects.validate(first_name=request.POST['first_name'], last_name=request.POST['last_name'], dob=request.POST['dob'], email=request.POST['email'], password=request.POST['password'], confirm_password=request.POST['confirm_password'])
	# If the inputs are all valid: 
	if result[0] == True:
		messages.success(request, 'You have successfully registered.')	
		return redirect(result[1]+'/summary')
	# Else, display the error and send back to index. 
	else:
		for i in result[1]:
			messages.error(request, i)
		return redirect('/')

# Login will use the login UserManager method and check if the hashed pw matches the input pw. 
def login(request):
	result = User.objects.login(email=request.POST['email'], password=request.POST['password'])	
	# If it matches: 
	if result[0] == True:
		messages.success(request, 'You have successfully logged in.')
		return redirect(result[1]+'/summary')
	# Else, display the error and send back to index. 
	else: 
		messages.error(request, result[1][0])
		return redirect('/')

# Log out user by clearing the session and sending back to the index. 
def logout(request):
	# request.session.pop('user') works just the same. 
	request.session.clear()
	return redirect('/')