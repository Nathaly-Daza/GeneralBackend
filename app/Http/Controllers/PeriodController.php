<?php

namespace App\Http\Controllers;

use App\Models\Period;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class PeriodController extends Controller
{
    // Método para obtener todos los períodos
    public function index()
    {
        try {
            // Intenta obtener todos los períodos
            $periods = Period::all();

            // Devuelve una respuesta JSON con los períodos obtenidos
            return response()->json([
                'status' => true,
                'data' => $periods
            ], 200);
        } catch (\Throwable $th) {
            // Maneja errores y devuelve una respuesta JSON con un mensaje de error
            return response()->json([
                'status' => false,
                'message' => $th->getMessage() // Devuelve el mensaje de error específico
            ], 500);
        }
    }
    // Método para almacenar un nuevo período
    public function store(Request $request)
    {
        // Reglas de validación para los datos de entrada
        $rules = [
            'peri_name' => 'required|string|max:15',
            'peri_start' => 'required|date',
            'peri_end' => 'required|date',
            'use_id' => 'required|integer|exists:users'
        ];

        // Validar los datos de entrada
        $validator = Validator::make($request->input(), $rules);

        if ($validator->fails()) {
            // Si la validación falla, devuelve una respuesta JSON con los errores de validación
            return response()->json([
                'status' => false,
                'message' => $validator->errors()->all()
            ], 400);
        } else {
            // Crear un nuevo período con los datos proporcionados
            $period = new Period($request->input());
            $period->save();

            // Registrar la acción en el sistema
            Controller::NewRegisterTrigger("Se realizó una inserción en la tabla Periods", 3, $request->use_id);

            // Devolver una respuesta JSON con un mensaje de éxito
            return response()->json([
                'status' => true,
                'message' => "The period '" . $period->peri_name . "' has been added successfully."
            ], 200);
        }
    }
    // Método para mostrar un período específico por su ID
    public function show($id)
    {
        // Buscar el período por su ID
        $period = Period::find($id);

        if ($period == null) {
            // Si el período no se encuentra, devuelve una respuesta JSON con un mensaje de error
            return response()->json([
                'status' => false,
                'message' => 'Could not find the period you are looking for'
            ], 404);
        } else {
            // Si se encuentra el período, devuelve una respuesta JSON con los datos del período
            return response()->json([
                'status' => true,
                'data' => $period
            ], 200);
        }
    }
    // Método para actualizar un período por su ID
    public function update(Request $request, $id)
    {
        // Buscar el período por su ID
        $period = Period::find($id);

        if ($period == null) {
            // Devuelve un mensaje de error si el período no se encuentra
            return response()->json([
                'status' => false,
                'message' => 'Could not find the required period'
            ], 404);
        } else {
            // Define reglas de validación para los datos de entrada
            $rules = [
                'peri_name' => 'required|string|max:15',
                'peri_start' => 'required|date',
                'peri_end' => 'required|date',
                'use_id' => 'required|integer|exists:users'
            ];

            // Validar los datos de entrada
            $validator = Validator::make($request->input(), $rules);

            if ($validator->fails()) {
                // Si la validación falla, devuelve una respuesta JSON con los errores de validación
                return response()->json([
                    'status' => false,
                    'message' => $validator->errors()->all()
                ], 400);
            } else {
                // Actualizar los datos del período y guardar los cambios
                $period->peri_name = $request->peri_name;
                $period->peri_start = $request->peri_start;
                $period->peri_end = $request->peri_end;
                $period->save();

                // Registrar la acción en el sistema
                Controller::NewRegisterTrigger("Se realizó una edición en la tabla Periods", 1, $request->use_id);

                // Devolver una respuesta JSON con un mensaje de éxito
                return response()->json([
                    'status' => true,
                    'message' => "The period '" . $period->peri_name . "' has been updated successfully."
                ], 200);
            }
        }
    }
    // Método para eliminar un período (no implementado completamente en este ejemplo)
    public function destroy(Period $period)
    {
        return response()->json([
            'status' => false,
            'message' => "You have no permission to delete this"
        ], 400);
    }
}
