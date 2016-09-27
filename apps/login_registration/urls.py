from django.conf.urls import url
from . import views

urlpatterns = [
	url(r'^$', views.index, name='index'),
	url(r'^(?P<id>\d+)/summary', views.summary, name='summary'), 
	url(r'^register', views.register, name='register'),
	url(r'^login', views.login, name='login'),
	url(r'^logout', views.logout, name='logout'),
]