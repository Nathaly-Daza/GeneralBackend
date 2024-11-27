<?php

namespace App\Http\Controllers;

use App\Models\Activity;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

// Método para obtener todas las actividades
class ActivityController extends Controller
{
    public function index()
    {
        try {
            // Obtener todas las actividades
            $activities = Activity::all();
            // Devolver las actividades en formato JSON con estado 200 (OK)
            return response()->json([
                'status' => true,
                'data' => $activities,
            ], 200);
        } catch (\Throwable $th) {
            // En caso de error, devolver un mensaje de error en formato JSON con estado 500 (Error del servidor)

            return response()->json([
                'status' => false,
                'message' => $th
            ], 500);
        }
    }
    // Método para almacenar una nueva actividad
    public function store(Request $request)
    {
        // Reglas de validación para los campos de entrada
        $rules = [
            'acti_name' => 'required|string|unique:activities|regex:/^[A-ZÑÁÉÍÓÚÜ ]+$/u',
            'acti_code' => 'required|unique:activities',
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
            // Crear una nueva actividad con los datos validados
            $activities = new Activity();
            $activities->acti_name = $request->acti_name;
            $activities->acti_code = $request->acti_code;
            $activities->save();
            Controller::NewRegisterTrigger("Se realizo una inserción en la tabla activities", 3, $request->use_id);;
            return response()->json([
                'status' => true,
                'message' => "The activity '" . $activities->acti_name . "' has been added succesfully."
            ], 200);
        }
    }
    // Método para mostrar una actividad específica por su ID
    public function show($activity)
    {
        // Buscar la actividad por su ID
        $activities = Activity::find($activity);

        // Si no se encuentra la actividad, devolver un mensaje de error en formato JSON
        if (!$activities) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'Could not find the activities you are looking for'],
            ], 400);
        } else {
            // Si se encuentra la actividad, devolverla en formato JSON con estado 200 (OK)
            return response()->json([
                'status' => true,
                'data' => $activities,
            ], 200);
        }
    }

    // Método para actualizar una actividad existente
    public function update(Request $request, $id)
    {

        // Reglas de validación para los campos de entrada
        $rules = [
            'acti_name' => 'required|string|regex:/^[A-ZÑÁÉÍÓÚÜ ]+$/u',
            'acti_code' => 'required',
            'use_id' => 'required|integer|exists:users'
        ];
        // Validar la solicitud de entrada según las reglas definidas
        $validator = Validator::make($request->input(), $rules);


        // Validar si los valores existen en la base de datos para actualizar
        $validate = Controller::validate_exists($request->acti_name, 'activities', 'acti_name', 'acti_id', $id);
        $validateCode = Controller::validate_exists($request->acti_code, 'activities', 'acti_code', 'acti_id', $id);

        // Si la validación falla o los valores ya existen, devolver un mensaje de error en formato JSON
        if ($validator->fails() || $validate == 0 || $validateCode == 0) {
            $msg = ($validate == 0 || $validateCode == 0) ? "value tried to register, it is already registered." : $validator->errors()->all();
            return response()->json([
                'status' => False,
                'message' => $msg
            ]);
        } else {

            // Encontrar la actividad por su ID
            $activities = Activity::find($id);

            // Actualizar los valores de la actividad
            $activities->acti_name = $request->acti_name;
            $activities->acti_code = $request->acti_code;
            $activities->save();

            // Registrar la actualización en el log (función personalizada)
            Controller::NewRegisterTrigger("Se realizo una edición en la tabla activities", 1, $request->use_id);;
            return response()->json([
                'status' => true,
                'data' => "The activity with ID: " . $activities->acti_id . " has been updated to '" . $activities->acti_name . "' succesfully.",
            ], 200);
        }
    }

    // Método para eliminar una actividad (no disponible)
    public function destroy(Activity $activity)
    {

         // Devolver un mensaje de función no disponible en formato JSON
        return response()->json([
            'status' => false,
            'message' => "Functions not available"
        ], 400);
    }
}
