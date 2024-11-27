<?php

namespace App\Http\Controllers;

use App\Models\Industry;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class IndustryController extends Controller
{
    public function index()
    {
        try {

            // Obtener todas las industrias
            $industries = Industry::all();

            // Devolver una respuesta JSON con las historias de becas obtenidas
            return response()->json([
                'status' => true,
                'data' => $industries,
            ], 200);
        } catch (\Throwable $th) {

            // Manejar cualquier excepción que pueda ocurrir durante la obtención de las historias de carrera
            return response()->json([
                'status' => false,
                'message' => $th
            ], 500);
        }
    }
    public function store(Request $request)
    {

        // Definir las reglas de validación para los datos de entrada
        $rules = [
            'ind_name' => 'required|string|unique:industries|regex:/^[A-ZÑÁÉÍÓÚÜ ]+$/u',
            'use_id' => 'required|integer|exists:users'
        ];

        // Validar los datos de entrada con las reglas definidas
        $validator = Validator::make($request->input(), $rules);

        // Devolver una respuesta JSON con los errores de validación si falla la validación
        if ($validator->fails()) {
            return response()->json([
                'status' => False,
                'message' => $validator->errors()->all()
            ]);
        } else {
            // Crear una nueva industria con los datos proporcionados
            $industries = new Industry();
            $industries->ind_name = $request->ind_name;
            $industries->save();

            // Disparar la acción de registro
            Controller::NewRegisterTrigger("Se realizo una inserción en la tabla industries", 3, $request->use_id);

            // Devolver una respuesta JSON indicando que se ha creado la industria exitosamente
            return response()->json([
                'status' => true,
                'message' => "The indrustry'" . $industries->ind_name . "' has been added succesfully."
            ], 200);
        }
    }
    public function show($industry)
    {

        // Buscar una industria por su ID
        $industries = Industry::find($industry);
        if (!$industries) {

            // Devolver un mensaje de error si no se encuentra la industria
            return response()->json([
                'status' => false,
                'data' => ['message' => 'Could not find the industries you are looking for'],
            ], 400);
        } else {

            // Devolver una respuesta JSON con la industria encontrada
            return response()->json([
                'status' => true,
                'data' => $industries,
            ], 200);
        }
    }
    public function update(Request $request, $id)
    {

        // Definir las reglas de validación para los datos de entrada
        $rules = [
            'ind_name' => 'required|string|regex:/^[A-ZÑÁÉÍÓÚÜ ]+$/u',
            'use_id' => 'required|integer|exists:users'
        ];

        // Validar los datos de entrada con las reglas definidas
        $validator = Validator::make($request->input(), $rules);

        // Validar si el nombre de la industria ya existe en otra entrada de la tabla
        $validate = Controller::validate_exists($request->ind_name, 'industries', 'ind_name', 'ind_id', $id);

        // Devolver una respuesta JSON con los errores de validación si falla la validación
        // o si el nombre de la industria ya está registrado en otra entrada
        if ($validator->fails() || $validate == 0) {
            $msg = ($validate == 0) ? "value tried to register, it is already registered." : $validator->errors()->all();
            return response()->json([
                'status' => False,
                'message' => $msg
            ]);
        } else {

             // Actualizar la industria con los datos proporcionados
            $industries = Industry::find($id);
            $industries->ind_name = $request->ind_name;
            $industries->save();

            // Disparar la acción de actualización
            Controller::NewRegisterTrigger("Se realizo una edición en la tabla industries", 1, $request->use_id);

            // Devolver una respuesta JSON indicando que se ha actualizado la industria exitosamente
            return response()->json([
                'status' => true,
                'data' => "The industry with ID: " . $industries->ind_id . " has been updated to '" . $industries->ind_name . "' succesfully.",
            ], 200);
        }
    }
    public function destroy(Industry $industry)
    {

        // Devolver una respuesta JSON indicando que se ha actualizado la industria exitosamente
        return response()->json([
            'status' => false,
            'message' => "Functions not available"
        ], 400);
    }
}
