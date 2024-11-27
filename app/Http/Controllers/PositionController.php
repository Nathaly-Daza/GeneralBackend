<?php

namespace App\Http\Controllers;

use App\Models\Position;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;


class PositionController extends Controller
{
    public function index()
    {
        try {
            // Seleccionar todas las posiciones desde la base de datos
            $positions = Position::select();

            // Retornar una respuesta JSON con las posiciones obtenidas
            return response()->json([
                'status' => true,
                'data' => $positions
            ], 200);
        } catch (\Throwable $th) {
            // Capturar cualquier error que ocurra y retornar una respuesta JSON con un mensaje de error
            return response()->json([
                'status' => false,
                'message' => "Error occurred while searching elements."
            ]);
        }
    }
    public function store(Request $request)
    {
        // Definir reglas de validación para los campos de entrada
        $rules = [
            'pos_name' => 'required|string|min:1|max:255|unique:positions|regex:/^[A-ZÑÁÉÍÓÚÜ\s]+$/',
            'are_id' =>'required|integer|exists:areas',
            'use_id' =>'required|integer|exists:users'
        ];

        // Ejecutar el validador con las reglas definidas
        $validator = Validator::make($request->input(), $rules);

        // Verificar si la validación falla y retornar mensajes de error si es así
        if ($validator->fails()) {
            return response()->json([
              'status' => false,
              'message' => $validator->errors()->all()
            ]);
        } else {
            // Si la validación pasa, crear una nueva instancia de Position y guardarla en la base de datos
            $position = new Position($request->input());
            $position->save();

            // Llamar al método estático NewRegisterTrigger para registrar la acción realizada
            Controller::NewRegisterTrigger("Se creó un registro en la tabla Position: $request->pos_name, $request->are_id ", 3, $request->use_id);

            // Retornar una respuesta JSON indicando que la posición fue creada exitosamente
            return response()->json([
              'status' => true,
              'message' => "The position: ".$position->pos_name." has been created."
            ], 200);
        }
    }

    public function show($id)
    {
        // Buscar la posición por su ID en la base de datos
        $position = Position::search($id);

        // Verificar si la posición no existe y retornar un mensaje de error si es así
        if ($position == null) {
            return response()->json([
               'status' => false,
                'data' => ['message' => 'The position requested was not found.']
            ], 400);
        } else {
            // Retornar una respuesta JSON con los detalles de la posición encontrada
            return response()->json([
                'status' => true,
                'data' => $position
            ]);
        }
    }
   public function update(Request $request, $id)
    {
        // Buscar la posición por su ID en la base de datos
        $position = Position::find($id);

        // Verificar si la posición no existe y retornar un mensaje de error si es así
        if ($position == null) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'The position requested was not found.']
            ], 400);
        } else {
            // Definir reglas de validación para los campos de entrada
            $rules = [
                'pos_name' => 'required|string|min:1|max:255|regex:/^[A-ZÑÁÉÍÓÚÜ\s]+$/',
                'are_id' =>'required|integer|exists:areas',
                'use_id' =>'required|integer|exists:users'
            ];

            // Ejecutar el validador con las reglas definidas
            $validator = Validator::make($request->input(), $rules);

            // Validar si la posición con el mismo nombre ya existe en la base de datos
            $validate = Controller::validate_exists($request->pos_name, 'positions', 'pos_name', 'pos_id', $id);

            // Verificar si la validación falla o si ya existe una posición con el mismo nombre
            if ($validator->fails() || $validate == 0) {
                $msg = ($validate == 0) ? "value tried to register, it is already registered." : $validator->errors()->all();

                return response()->json([
                  'status' => false,
                  'message' => $msg
                ]);
            } else {
                // Si la validación pasa, actualizar la posición con los nuevos datos proporcionados
                $position->pos_name = $request->pos_name;
                $position->are_id = $request->are_id;
                $position->save();

                // Llamar al método estático NewRegisterTrigger para registrar la acción realizada
                Controller::NewRegisterTrigger("Se realizó una edición de datos en la tabla position del dato: $id con los datos: $request->pos_name, $request->are_id ", 1, $request->use_id);

                // Retornar una respuesta JSON indicando que la posición fue actualizada exitosamente
                return response()->json([
                  'status' => true,
                  'message' => "The position: ".$position->pos_name." has been updated successfully."
                ], 200);
            }
        }
    }
    public function destroy(Position $position)
    {
        // Retorna una respuesta JSON indicando que la función no está disponible para este método
        return response()->json([
           'status' => false,
           'message' => "FUNCTION NOT AVAILABLE"
        ], 400);
    }
}
