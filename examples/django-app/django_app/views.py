import time

from django.http import HttpResponse


def hello(request):
    time.sleep(1)
    return HttpResponse('Hello World!')
