<?php

namespace App\Http\Controllers;

use App\Models\Diseases;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class DiseasesController extends Controller
{
    public function index()
    {
        try {

            // Obtener todas las enfermedades
            $disease = Diseases::all();

            // Devolver una respuesta JSON con las enfermedades
            return response()->json([
                'status' => true,
                'data' => $disease,
            ], 200);
        } catch (\Throwable $th) {

            // Manejar excepciones y devolver un mensaje de error
            return response()->json([
                'status' => false,
                'message' => "Error in index, not found elements"
            ], 500);
        }
    }
    public function store(Request $request)
    {

        // Reglas de validación para los datos de la enfermedad
        $rules = [
            'dis_name' => 'required|string|min:1|max:255|unique:diseases|regex:/^[A-ZÑÁÉÍÓÚÜ\s]+$/',
            'use_id' =>'required|integer|exists:users'
        ];

        // Realizar la validación de los datos recibidos
        $validator = Validator::make($request->input(), $rules);

        // Si la validación falla, devolver los errores
        if ($validator->fails()) {
            return response()->json([
                'status' => False,
                'message' => $validator->errors()->all()
            ]);
        } else {

             // Crear una nueva enfermedad
            $disease = new Diseases(($request->input()));
            $disease->save();

            // Disparar un nuevo registro
            Controller::NewRegisterTrigger("Se creo un registro en la tabla Diseases: $request->dis_name", 3,$request->use_id);

            // Devolver una respuesta JSON de éxito
            return response()->json([
                'status' => true,
                'message' => "The Diseases: " . $disease->dis_name . " has been created."
            ], 200);
        }
    }
    public function show($id)
    {

        // Buscar una enfermedad por su ID
        $disease = Diseases::find($id);

        // Si no se encuentra la enfermedad, devolver un mensaje de error
        if ($disease == null) {
            return response()->json([
                'status' => False,
                'data' => ['message' => 'The disease requested not found'],
            ], 400);

        } else {

            // Devolver la enfermedad encontrada
            return response()->json([
                'status' => true,
                'data' => $disease
            ]);
        }
    }
    public function update(Request $request, $id)
    {

         // Buscar la enfermedad por su ID
        $disease = Diseases::find($id);

        // Si la enfermedad no se encuentra, devolver un mensaje de error
        if ($disease == null) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'The disease requested not found'],
            ], 400);
        } else {

            // Reglas de validación para actualizar los datos de la enfermedad
            $rules = [
                'dis_name' => 'required|string|min:1|max:255|regex:/^[A-ZÑÁÉÍÓÚÜ\s]+$/',
                'use_id' =>'required|integer|exists:users'
            ];

            // Realizar la validación de los datos recibidos
            $validator = Validator::make($request->input(), $rules);

            // Validar que no exista otra enfermedad con el mismo nombre
            $validate = Controller::validate_exists($request->dis_name, 'diseases', 'dis_name', 'dis_id', $id);

            // Si la validación falla o ya existe otra enfermedad con el mismo nombre, devolver los errores
            if ($validator->fails() || $validate == 0) {
                $msg = ($validate == 0) ? "value tried to register, it is already registered." : $validator->errors()->all();
                return response()->json([
                    'status' => False,
                    'message' => $msg
                ]);
            } else {
                // Actualizar los datos de la enfermedad
                $disease = Diseases::find($id);
                $disease->dis_name = $request->dis_name;
                $disease->save();

                // Disparar un nuevo registro
                Controller::NewRegisterTrigger("Se realizo una Edicion de datos en la tabla Diseases del dato: id->$id", 1, $request->use_id);

                // Devolver una respuesta JSON de éxito
                return response()->json([
                    'status' => true,
                    'data' => "The Diseases: " . $disease->dis_name . " has been update."
                ], 200);
            }
        }
    }
    public function destroy(Diseases $diseases)
    {

        // Devolver un mensaje indicando que esta función no está disponible
        return response()->json([
            'status' => false,
            'message' => "Functions not available"
        ], 400);
    }
}
