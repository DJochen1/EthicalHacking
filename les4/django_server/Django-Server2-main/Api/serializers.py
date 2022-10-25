from rest_framework import serializers


class studentSerializer(serializers.Serializer):
    nombre = serializers.CharField()
    promedio = serializers.FloatField()
    color = serializers.CharField()