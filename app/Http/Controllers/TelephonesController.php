<?php

namespace App\Http\Controllers;

use App\Models\telephone;
use Illuminate\Support\Facades\Validator;
use Illuminate\Http\Request;
class TelephonesController extends Controller
{
    public function index()
    {
        try {
            // Seleccionar todos los registros de teléfonos
            $telephone = telephone::select();

            // Retornar una respuesta JSON con estado verdadero y datos de los teléfonos
            return response()->json([
                'status' => true,
                'data' => $telephone
            ], 200);
        } catch (\Throwable $th) {
            // Capturar cualquier excepción y devolver una respuesta JSON con estado falso y mensaje de error
            return response()->json([
                'status' => false,
                'message' => $th
            ], 500);
        }
    }
    public function store(Request $request)
    {
        // Definir reglas de validación para los datos del teléfono a almacenar
        $rules = [
            'tel_number' => ['required', 'regex:/^([0-9\s\-\+\(\)]*)$/', 'min:7', 'max:15'],
            'tel_description' => 'string|max:255',
            'per_id' => 'required|integer|exists:persons',
            'use_id' => 'required|integer|exists:users'
        ];

        // Validar los datos de entrada con las reglas definidas
        $validator = Validator::make($request->input(), $rules);

        if ($validator->fails()) {
            // Retornar una respuesta JSON con estado falso y mensajes de error de validación
            return response()->json([
                'status' => false,
                'message' => $validator->errors()->all()
            ]);
        } else {
            // Crear una nueva instancia de Telephone con los datos del request
            $telephone = new telephone($request->input());
            $telephone->save();

            // Registrar la acción de inserción de teléfono
            Controller::NewRegisterTrigger("Se realizó una inserción de datos en la tabla telephones", 3, $request->use_id);

            // Retornar una respuesta JSON con estado verdadero, mensaje de éxito y datos del teléfono agregado
            return response()->json([
                'status' => true,
                'message' => "The Telephone number ".$telephone->tel_number." has been added succesfully.",
                'data' => $telephone->tel_id
            ], 200);
        }
    }
     public function show($id)
    {
        // Buscar un teléfono específico por su ID
        $telephone = telephone::search($id);

        if ($telephone == null) {
            // Retornar una respuesta JSON con estado falso y mensaje de teléfono no encontrado
            return response()->json([
                'status' => false,
                'data' => ['message' => 'Could not find the telephone number you are looking for']
            ], 400);
        } else {
            // Retornar una respuesta JSON con estado verdadero y datos del teléfono encontrado
            return response()->json([
                'status' => true,
                'data' => $telephone
            ], 200);
        }
    }
    public function update(Request $request, $id)
    {
        // Buscar un teléfono para actualizar por su ID
        $telephone = Telephone::find($id);

        if ($telephone == null) {
            // Retornar una respuesta JSON con estado falso y mensaje de teléfono no encontrado
            return response()->json([
                'status' => false,
                'data' => ['message' => 'Could not find required telephone']
            ], 400);
        } else {
            // Definir reglas de validación para los datos del teléfono a actualizar
            $rules = [
                'tel_number' => ['required', 'regex:/^([0-9\s\-\+\(\)]*)$/', 'min:7', 'max:15'],
                'tel_description' => 'string|max:255',
                'per_id' => 'required|integer|exists:persons',
                'use_id' => 'required|integer|exists:users'
            ];

            // Validar los datos de entrada con las reglas definidas
            $validator = Validator::make($request->input(), $rules);

            if ($validator->fails()) {
                // Retornar una respuesta JSON con estado falso y mensajes de error de validación
                return response()->json([
                    'status' => false,
                    'message' => $validator->errors()->all()
                ]);
            } else {
                // Actualizar los datos del teléfono y guardar los cambios
                $telephone->tel_number = $request->tel_number;
                $telephone->tel_description = $request->tel_description;
                $telephone->per_id = $request->per_id;
                $telephone->save();

                // Registrar la acción de actualización de teléfono
                Controller::NewRegisterTrigger("Se realizó una actualización de datos en la tabla telephones", 1, $request->use_id);

                // Retornar una respuesta JSON con estado verdadero y mensaje de éxito
                return response()->json([
                    'status' => true,
                    'message' => "The telephone ".$telephone->tel_number." has been updated succesfully."
                ], 200);
            }
        }
    }
    public function destroy()
    {
        // Retornar una respuesta JSON indicando que la función no está disponible
        return response()->json([
            'status' => false,
            'message' => "You have no permission to delete this"
         ], 400);
    }
}
