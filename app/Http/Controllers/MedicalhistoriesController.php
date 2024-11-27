<?php

namespace App\Http\Controllers;

use App\Models\medicalhistories;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class MedicalhistoriesController extends Controller
{
    public function index()
    {
        try {
            // Intentar obtener todos los historiales médicos
            $medicalHistory = Medicalhistories::select();
            // Devolver una respuesta JSON con los historiales médicos obtenidos
            return response()->json([
                'status' => true,
                'data' => $medicalHistory
            ], 200);
        } catch (\Throwable $th) {
            // Manejar errores y devolver una respuesta JSON con un mensaje de error
            return response()->json([
                'status' => false,
                'message' => $th
            ], 500);
        }
    }

    public function store(Request $request)
    {
        // Definir reglas de validación para los datos de entrada
        $rules = [
            'per_id' => 'required|integer|exists:persons',
            'dis_id' => 'required|integer|exists:diseases',
        ];

        // Validar los datos de entrada
        $validator = Validator::make($request->input(), $rules);
        if ($validator->fails()) {

            // Devolver una respuesta JSON con los errores de validación si falla la validación
            return response()->json([
                'status' => False,
                'message' => $validator->errors()->all()
            ], 400);
        } else {

            // Crear una nueva instancia de Medicalhistories con los datos proporcionados
            $medicalHistory = new medicalhistories($request->input());
            $medicalHistory->med_his_status = 1;
            $medicalHistory->save();

            // Registrar la acción en un sistema de seguimiento
            Controller::NewRegisterTrigger("Se realizó una inserción de datos en la tabla Medical Histories", 3, $request->use_id);

            // Devolver una respuesta JSON indicando que el historial médico ha sido creado exitosamente
            return response()->json([
                'status' => True,
                'message' => "The medical history " . $medicalHistory->per_name . " has been added succesfully.",
                'data' => $medicalHistory->med_his_id
            ], 200);
        }
    }
    public function show($id)
    {

        // Buscar un historial médico por su ID
        $medicalHistory = medicalhistories::search($id);
        if ($medicalHistory == null) {

            // Devolver un mensaje de error si no se encuentra el historial médico
            return response()->json([
                'status' => false,
                'data' => ['message' => 'Could not find the medical history you are looking for']
            ], 400);
        } else {

            // Devolver una respuesta JSON con el historial médico encontrado
            return response()->json([
                'status' => true,
                'data' => $medicalHistory
            ], 200);
        }
    }
    public function update(Request $request, $id)
    {

        // Buscar el historial médico por su ID
        $medicalHistory = medicalhistories::find($id);

        // Devolver un mensaje de error si el historial médico no se encuentra
        if ($medicalHistory == null) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'Could not find required medical history']
            ], 400);
        } else {

            // Definir reglas de validación para los datos de entrada
            $rules = [
                'per_id' => 'required|integer',
                'dis_id' => 'required|integer',
                'med_his_status' => 'required|integer',
                'use_id' => 'required|integer|exists:users'
            ];

            // Validar los datos de entrada
            $validator = Validator::make($request->input(), $rules);

            // Devolver una respuesta JSON con los errores de validación si falla la validación
            if ($validator->fails()) {
                return response()->json([
                    'status' => False,
                    'message' => $validator->errors()->all()
                ], 400);
            } else {

                // Actualizar el historial médico con los datos proporcionados
                $medicalHistory->per_id = $request->per_id;
                $medicalHistory->dis_id = $request->dis_id;
                $medicalHistory->med_his_status = $request->med_his_status;
                $medicalHistory->save();

                // Registrar la acción en un sistema de seguimiento
                Controller::NewRegisterTrigger("Se realizó una actualización de datos en la tabla medical histories", 1, $request->use_id);

                // Devolver una respuesta JSON indicando que el historial médico ha sido actualizado exitosamente
                return response()->json([
                    'status' => True,
                    'message' => "The medical history: " . $medicalHistory->med_his_id . " has been updated succesfully."
                ], 200);
            }
        }
    }
    public function destroy()
    {

         // Devolver un mensaje indicando que la función no está disponible para eliminar un historial médico
         return response()->json([
            'status' => false,
            'message' => "You have no permission to delete this"
        ], 400);
    }
}
