<?php

namespace App\Http\Controllers;

use App\Models\Locality;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class LocalityController extends Controller
{
    public function index()
    {
        try {

            // Intentar obtener todas las localidades
            $localities = Locality::all();

            // Devolver una respuesta JSON con las localidades obtenidas
            return response()->json([
                'status' => true,
                'data' => $localities
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
            'loc_name' => 'required|string|min:1|max:255|unique:localities|regex:/^[A-ZÑÁÉÍÓÚÜ\s]+$/',
            'use_id' => 'required|integer|exists:users'
        ];

        // Validar los datos de entrada con las reglas
        $validator = Validator::make($request->input(), $rules);
        if ($validator->fails()) {

            // Devolver una respuesta JSON con los errores de validación si falla la validación
            return response()->json([
                'status' => false,
                'message' => $validator->errors()->all()
            ]);
        } else {

            // Crear una nueva instancia de Localidad con los datos proporcionados y guardarla
            $localities = new Locality($request->input());
            $localities->save();

            //Disparar la accion de registro
            Controller::NewRegisterTrigger("Se creo un registro en la tabla Locality : $request->loc_name ", 3, $request->use_id);

            // Devolver una respuesta JSON indicando que la localidad ha sido creada exitosamente
            return response()->json([
                'status' => true,
                'message' => "The locality: " . $localities->loc_name . " has been created."
            ], 200);
        };
    }
    public function show($id)
    {

        // Buscar una localidad por su ID
        $localities = Locality::find($id);
        if ($localities == null) {

            // Devolver un mensaje de error si no se encuentra la localidad
            return response()->json([
                'status' => false,
                'data' => ['message' => 'The Locality requested was not found']
            ], 400);
        } else {

            // Devolver una respuesta JSON con la localidad encontrada
            return response()->json([
                'status' => true,
                'data' => $localities
            ], 200);
        }
    }
    public function update(Request $request, $id)
    {

        // Buscar la localidad por su ID
        $locality = Locality::find($id);
        if ($locality == null) {

            // Devolver un mensaje de error si la localidad no se encuentra
            return response()->json([
                'status' => false,
                'data' => ['message' => 'The Locality requested was not found']
            ], 400);
        } else {

            // Definir reglas de validación para los datos de entrada
            $rules = [
                'loc_name' => 'required|string|min:1|max:255|regex:/^[A-ZÑÁÉÍÓÚÜ\s]+$/',
            ];

            // Validar los datos de entrada
            $validator = Validator::make($request->input(), $rules);

            // Validar si la nueva localidad ya existe o no
            $validate = Controller::validate_exists($request->loc_name, 'localities', 'loc_name', 'loc_id', $id);
            if ($validator->fails() || $validate == 0) {
                // Devolver una respuesta JSON con los errores de validación o si la localidad ya existe
                $msg = ($validate == 0) ? "value tried to register, it is already registered." : $validator->errors()->all();
                return response()->json([
                    'status' => false,
                    'message' => $msg
                ]);
            } else {

                // Actualizar la localidad con los datos proporcionados
                $locality->loc_name = $request->loc_name;
                $locality->save();

                // Disparar la accion de actualización
                Controller::NewRegisterTrigger("Se realizo una Edicion de datos en la tabla Locality del dato: $id con el dato: $request->loc_name", 1, $request->use_id);

                // Devolver una respuesta JSON indicando que la localidad ha sido actualizada exitosamente
                return response()->json([
                    'status' => true,
                    'message' => "The locality: .$locality->loc_name. has been updated successfully"
                ], 200);
            };
        }
    }
    public function destroy(Locality $locality)
    {

        // Devolver una respuesta JSON indicando que la función no está disponible para eliminar una localidad
        return response()->json([
            'status' => false,
            'message' => "FUNCTION NOT AVAILABLE"
        ], 400);
    }
}
