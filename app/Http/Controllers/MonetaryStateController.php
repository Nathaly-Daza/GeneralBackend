<?php

namespace App\Http\Controllers;

use App\Models\MonetaryState;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class MonetaryStateController extends Controller
{
    public function index()
    {
        try {
            // Intentar obtener todos los estados monetarios
            $monState = MonetaryState::all();
            // Devolver una respuesta JSON con los estados monetarios obtenidos
            return response()->json([
                'status' => true,
                'data' => $monState
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
            'mon_sta_name' => 'required|unique:monetary_states|string|min:1|max:50|regex:/^[A-ZÑÁÉÍÓÚÜ\s]+$/u',
            'use_id' => 'required|integer|exists:users'
        ];
        // Validar los datos de entrada
        $validator = Validator::make($request->input(), $rules);
        if ($validator->fails()) {
            // Devolver una respuesta JSON con los errores de validación si falla la validación
            return response()->json([
                'status' => False,
                'message' => $validator->errors()->all()
            ]);
        } else {
            // Crear una nueva instancia de MonetaryState con los datos proporcionados
            $monState = new MonetaryState($request->input());
            $monState->save();
            // Registrar la acción en un sistema de seguimiento
            Controller::NewRegisterTrigger("An insertion was made in the monetary states table", 3, $request->use_id);
            // Devolver una respuesta JSON indicando que el estado monetario ha sido creado exitosamente
            return response()->json([
                'status' => True,
                'message' => "The economic state type '" . $monState->mon_sta_name . "' has been created successfully."
            ], 200);
        }
    }

    public function show($id)
    {
        // Buscar un estado monetario por su ID
        $monState = MonetaryState::find($id);
        if ($monState == null) {
            // Devolver un mensaje de error si no se encuentra el estado monetario
            return response()->json([
                'status' => false,
                'data' => ['message' => 'The requested economic state was not found']
            ], 400);
        } else {
            // Devolver una respuesta JSON con el estado monetario encontrado
            return response()->json([
                'status' => true,
                'data' => $monState
            ]);
        }
    }

    public function update(Request $request, $id)
    {
        // Buscar el estado monetario por su ID
        $monState = MonetaryState::find($id);
        if ($monState == null) {
            // Devolver un mensaje de error si el estado monetario no se encuentra
            return response()->json([
                'status' => false,
                'data' => ['message' => 'The requested economic state was not found']
            ], 400);
        } else {
            // Definir reglas de validación para los datos de entrada
            $rules = [
                'mon_sta_name' => 'required|string|min:1|max:50|regex:/^[A-ZÑÁÉÍÓÚÜ\s]+$/u',
                'use_id' => 'required|integer|exists:users'
            ];
            // Validar los datos de entrada y verificar si el nombre del estado monetario ya existe
            $validator = Validator::make($request->input(), $rules);
            $validate = Controller::validate_exists($request->mon_sta_name, 'monetary_states', 'mon_sta_name', 'mon_sta_id', $id);

            if ($validator->fails() || $validate == 0) {
                // Devolver una respuesta JSON con los errores de validación si falla la validación
                $msg = ($validate == 0) ? "value tried to register, it is already registered." : $validator->errors()->all();
                return response()->json([
                    'status' => False,
                    'message' => $msg
                ]);
            } else {
                // Actualizar el estado monetario con los datos proporcionados
                $monState->mon_sta_name = $request->mon_sta_name;
                $monState->save();
                // Registrar la acción en un sistema de seguimiento
                Controller::NewRegisterTrigger("An update was made in the monetary states table", 1, $request->use_id);
                // Devolver una respuesta JSON indicando que el estado monetario ha sido actualizado exitosamente
                return response()->json([
                    'status' => True,
                    'message' => "The economic state '" . $monState->mon_sta_name . "' has been updated successfully."
                ], 200);
            }
        }
    }

    public function destroy($proj_id, $use_id, $id)
    {
        // Devolver un mensaje indicando que la función no está disponible para eliminar un estado monetario
        return response()->json([
            'status' => false,
            'message' => 'Function not available'
        ]);
    }
}
