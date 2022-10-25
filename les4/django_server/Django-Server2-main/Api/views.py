from rest_framework.response import Response
from rest_framework.decorators import api_view
from .serializers import studentSerializer
from rest_framework.parsers import JSONParser
from rest_framework.decorators import parser_classes


class Student:
    def __init__(self, nombre, promedio, color) -> None:
        self.nombre = nombre
        self.promedio = promedio
        self.color = color

students = [
    Student(nombre="Miguel", promedio=8.9, color="Verde"),
    Student(nombre="Miguel", promedio=8.9, color="Verde"),
    Student(nombre="Miguel", promedio=8.9, color="Verde"),
]

@api_view(['Get'])
def getData(request):
    serializer = studentSerializer(students, many=True)
    return Response(serializer.data)

@api_view(['POST'])
@parser_classes([JSONParser])
def addData(request):
    print(request.data)
    return Response({'received data': request.data})