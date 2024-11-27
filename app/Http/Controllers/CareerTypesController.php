<?php

namespace App\Http\Controllers;

use App\Models\Career_Types;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class CareerTypesController extends Controller
{

    // Método para listar todos los tipos de carrera
    public function index()
    {
        // Obtener todos los tipos de carrera
        $career_types = Career_Types::all();
        return response()->json([
            'status' => true,
            'data' => $career_types,
        ], 200);
    }

    // Método para crear un nuevo tipo de carrera
    public function store(Request $request)
    {

        // Reglas de validación para los campos de entrada
        $rules = [
            'car_typ_name' => 'required|unique:career_types|string|regex:/^[A-ZÑÁÉÍÓÚÜ ]+$/u',
            'use_id' => 'required|integer|exists:users'
        ];

        // Validar la solicitud de entrada según las reglas definidas
        $validator = Validator::make($request->input(), $rules);

        // Si la validación falla, devolver los errores en formato JSON
        if ($validator->fails()) {
            return response()->json([
                'status' => False,
                'message' => $validator->errors()->all()
            ]);
        } else {

            // Crear un nuevo tipo de carrera
            $career_types = new Career_Types();
            $career_types->car_typ_name = $request->car_typ_name;
            $career_types->save();

            // Registrar el evento de inserción
            Controller::NewRegisterTrigger("Se realizo una inserción en la tabla career types", 3, $request->use_id);

            // Devolver un mensaje de éxito en formato JSON
            return response()->json([
                'status' => true,
                'message' => "The career type '" . $career_types->car_typ_name . "' has been added succesfully."
            ], 200);
        }
    }

    // Método para mostrar un tipo de carrera específico
    public function show($career_Types)
    {
        // Buscar el tipo de carrera por ID
        $careers_types_types = Career_Types::find($career_Types);

        // Si no se encuentra, devolver un mensaje de error
        if (!$careers_types_types) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'Could not find the career types you are looking for'],
            ], 400);
        } else {

            // Devolver el tipo de carrera en formato JSON
            return response()->json([
                'status' => true,
                'data' => $careers_types_types,
            ], 200);
        }
    }

    // Método para actualizar un tipo de carrera
    public function update(Request $request, $career_Types)
    {

        // Reglas de validación para los campos de entrada
        $rules = [
            'car_typ_name' => 'required|string|regex:/^[A-ZÑÁÉÍÓÚÜ ]+$/u',
            'use_id' => 'required|integer|exists:users'
        ];

        // Validar la solicitud de entrada según las reglas definidas
        $validator = Validator::make($request->input(), $rules);

        // Validar que el nombre del tipo de carrera no exista ya en otro tipo de carrera
        $validate = Controller::validate_exists($request->car_typ_name, 'career_types', 'car_typ_name', 'car_typ_id', $career_Types);

        // Si la validación falla o el nombre ya existe, devolver un mensaje de error
        if ($validator->fails() || $validate == 0) {
            $msg = ($validate == 0) ? "value tried to register, it is already registered." : $validator->errors()->all();
            return response()->json([
                'status' => False,
                'message' => $msg
            ]);
        } else {

            // Buscar el tipo de carrera por ID
            $careers_types = Career_Types::find($career_Types);
            $careers_types->car_typ_name = $request->car_typ_name;
            $careers_types->save();

            // Registrar el evento de actualización
            Controller::NewRegisterTrigger("Se realizo una edición en la tabla careers_types", 1, $request->use_id);

            // Devolver un mensaje de éxito en formato JSON
            return response()->json([
                'status' => true,
                'data' => "The career type with ID: " . $careers_types->car_typ_id . " has been updated to '" . $careers_types->car_typ_name . "' succesfully.",
            ], 200);
        }
    }

    // Método para eliminar un tipo de carrera (actualmente no disponible)
    public function destroy(Career_Types $career_Types)
    {
        return response()->json([
            'status' => false,
            'message' => "Functions not available"
        ], 400);
    }
}
