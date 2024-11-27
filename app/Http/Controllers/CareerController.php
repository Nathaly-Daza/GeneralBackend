<?php

namespace App\Http\Controllers;

use App\Models\Career;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class CareerController extends Controller
{
    // Método para listar todas las carreras
    public function index()
    {
        try {
            // Obtener todas las carreras
            $careers = Career::select();
            return response()->json([
                'status' => true,
                'data' => $careers,
            ], 200);
        } catch (\Throwable $th) {
            // Manejo de excepciones
            return response()->json([
                'status' => false,
                'message' => $th
            ], 500);
        }
    }

    // Método para crear una nueva carrera
    public function store(Request $request)
    {
        // Reglas de validación para los campos de entrada
        $rules = [
            'car_name' => 'required|unique:careers|string|regex:/^[A-ZÑÁÉÍÓÚÜ ]+$/u',
            'car_typ_id' => 'required|integer|exists:career_types',
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

            // Crear una nueva carrera
            $careers = new Career();
            $careers->car_name = $request->car_name;
            $careers->car_typ_id = $request->car_typ_id;
            $careers->save();

            // Registrar el evento de inserción
            Controller::NewRegisterTrigger("Se realizo una inserción en la tabla careers", 3, $request->use_id);

            // Devolver un mensaje de éxito en formato JSON
            return response()->json([
                'status' => true,
                'message' => "The career '" . $careers->car_name . "' has been added succesfully."
            ], 200);
        }
    }

    // Método para mostrar una carrera específica
    public function show($career)
    {

        // Buscar la carrera por ID o nombre
        $careers = Career::search($career);
        // Si la carrera no se encuentra, devolver un mensaje de error
        if (!$careers) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'Could not find the career you are looking for'],
            ], 400);
        } else {
            // Devolver la carrera en formato JSON
            return response()->json([
                'status' => true,
                'data' => $careers,
            ], 200);
        }
    }

    // Método para actualizar una carrera
    public function update(Request $request, $career)
    {

        // Reglas de validación para los campos de entrada
        $rules = [
            'car_name' => 'required|string|regex:/^[A-ZÑÁÉÍÓÚÜ ]+$/u',
            'car_typ_id' => 'required|integer|exists:career_types',
            'use_id' => 'required|integer|exists:users'
        ];

        // Validar la solicitud de entrada según las reglas definidas
        $validator = Validator::make($request->input(), $rules);

        // Validar que el nombre de la carrera no exista ya en otra carrera
        $validate = Controller::validate_exists($request->car_name, 'careers', 'car_name', 'car_id', $career);

        // Si la validación falla o el nombre ya existe, devolver un mensaje de error
        if ($validator->fails() || $validate == 0) {
            $msg = ($validate == 0) ? "value tried to register, it is already registered." : $validator->errors()->all();
            return response()->json([
                'status' => False,
                'message' => $msg
            ]);
        } else {

            // Buscar la carrera por ID
            $careers = Career::find($career);
            $careers->car_name = $request->car_name;
            $careers->car_typ_id = $request->car_typ_id;
            $careers->save();

             // Registrar el evento de actualización
            Controller::NewRegisterTrigger("Se realizo una edición en la tabla careers", 1, $request->use_id);

            // Devolver un mensaje de éxito en formato JSON
            return response()->json([
                'status' => true,
                'data' => "The career with ID: " . $careers->car_id . " has been updated to '" . $careers->car_name . "' succesfully.",
            ], 200);
        }
    }

    // Método para eliminar una carrera (actualmente no disponible)
    public function destroy(Career $career)
    {
        return response()->json([
            'status' => false,
            'message' => "Functions not available"
        ], 400);
    }
}
