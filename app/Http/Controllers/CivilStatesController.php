<?php

namespace App\Http\Controllers;

use App\Models\civilStates;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class CivilStatesController extends Controller
{
    // Método para listar todos los estados civiles
    public function index()
    {
        try {
            // Obtener todos los registros de la tabla 'civil_states'
            $civilStates = civilStates::all();
            return response()->json([
                'status' => true,
                'data' => $civilStates
            ], 200);
        } catch (\Throwable $th) {
            // Manejar errores y devolver un mensaje de error
            return response()->json([
                'status' => false,
                'message' => $th
            ]);
        }
    }

    // Método para crear un nuevo estado civil
    public function store(Request $request)
    {
        // Reglas de validación para los campos de entrada
        $rules = [
            'civ_sta_name' => 'required|string|min:1|max:255|unique:civil_states|regex:/^[A-ZÑÁÉÍÓÚÜ\s]+$/',
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

            // Crear un nuevo registro en la tabla 'civil_states'
            $civilStates = new civilStates($request->input());
            $civilStates->save();

            // Registrar el evento de creación
            Controller::NewRegisterTrigger("Se creo un registro en la tabla civilStates: $request->civ_sta_name ", 3, $request->use_id);

            // Devolver un mensaje de éxito en formato JSON
            return response()->json([
                'status' => True,
                'message' => "The civil state: " . $civilStates->civ_sta_name . " has been created."
            ], 200);
        }
    }

    // Método para mostrar un estado civil específico
    public function show($id)
    {

        // Buscar el estado civil por ID
        $civilState = civilStates::find($id);
        // Si no se encuentra, devolver un mensaje de error
        if ($civilState == null) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'The requested civil state is not found']
            ], 400);
        } else {

            // Devolver el estado civil en formato JSON
            return response()->json([
                'status' => true,
                'data' => $civilState
            ]);
        }
    }

    // Método para actualizar un estado civil
    public function update(Request $request, $id)
    {

        // Reglas de validación para los campos de entrada
        $rules = [
            'civ_sta_name' => 'required|string|min:1|max:255|regex:/^[A-ZÑÁÉÍÓÚÜ\s]+$/',
            'use_id' => 'required|integer|exists:users'
        ];

        // Validar la solicitud de entrada según las reglas definidas
        $validator = Validator::make($request->input(), $rules);

        // Validar que el nombre del estado civil no exista ya en otro registro
        $validate = Controller::validate_exists($request->civ_sta_name, 'civil_states', 'civ_sta_name', 'civ_sta_id', $id);

        // Si la validación falla o el nombre ya existe, devolver un mensaje de error
        if ($validator->fails() || $validate == 0) {
            $msg = ($validate == 0) ? "value tried to register, it is already registered." : $validator->errors()->all();
            return response()->json([
                'status' => False,
                'message' => $msg
            ]);
        } else {

             // Buscar el estado civil por ID
            $civilState = civilStates::find($id);
            $msg = $civilState->civ_sta_name;

             // Si no se encuentra el estado civil, devolver un mensaje de error
            if ($civilState == null) {
                return response()->json([
                    'status' => false,
                    'data' => ['message' => 'The requested civil state is not found']
                ], 400);
            } else {

                 // Actualizar el registro en la tabla 'civil_states'
                $civilState->civ_sta_name = $request->civ_sta_name;
                $civilState->save();

                // Registrar el evento de actualización
                Controller::NewRegisterTrigger("Se realizo una Edicion de datos en la tabla CivilStates del dato: $msg con el dato: $request->civ_sta_name", 1, $request->use_id);
                // Devolver un mensaje de éxito en formato JSON
                return response()->json([
                    'status' => True,
                    'message' => "The civil state: " . $civilState->civ_sta_name . " has been update."
                ], 200);
            }
        }
    }

    // Método para eliminar un estado civil (actualmente no disponible)
    public function destroy(civilStates $civilStates)
    {
        return response()->json([
            'status' => false,
            'message' => "FUNCTION NOT AVAILABLE"
        ], 400);
    }
}
