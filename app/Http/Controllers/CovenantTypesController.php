<?php

namespace App\Http\Controllers;

use App\Models\Covenant_types;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class CovenantTypesController extends Controller
{
    public function index()
    {
        try {
            // Obtener todos los tipos de convenio
            $covenant_type = Covenant_types::all();

            // Devolver una respuesta JSON con los tipos de convenio
            return response()->json([
                'status' => true,
                'data' => $covenant_type,
            ], 200);
        } catch (\Throwable $th) {

            // Manejar excepciones y devolver un mensaje de error
            return response()->json([
                'status' => false,
                'message' => $th
            ], 500);
        }
    }
    public function store(Request $request)
    {

        // Reglas de validación para los datos del tipo de convenio
        $rules = [
            'cov_typ_name' => 'required|string|unique:covenant_types|regex:/^[A-ZÑÁÉÍÓÚÜ ]+$/u',
            'use_id' => 'required|integer|exists:users'
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

            // Crear un nuevo tipo de convenio
            $covenant_type = new Covenant_types();
            $covenant_type->cov_typ_name = $request->cov_typ_name;
            $covenant_type->save();

             // Disparar un nuevo registro
            Controller::NewRegisterTrigger("Se realizo una inserción en la tabla covenant types", 3, $request->use_id);

            // Devolver una respuesta JSON de éxito
            return response()->json([
                'status' => true,
                'message' => "The covenant type '" . $covenant_type->cov_typ_name . "' has been added succesfully."
            ], 200);
        }
    }
    public function show($covenant_Types)
    {

        // Buscar un tipo de convenio por su ID
        $covenant_type = Covenant_types::find($covenant_Types);

        // Si no se encuentra el tipo de convenio, devolver un mensaje de error
        if (!$covenant_type) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'Could not find the covenant types you are looking for'],
            ], 400);
        } else {

            // Devolver el tipo de convenio encontrado
            return response()->json([
                'status' => true,
                'data' => $covenant_type,
            ], 200);
        }
    }
    public function update(Request $request, $id)
    {

        // Reglas de validación para actualizar los datos del tipo de convenio
        $rules = [
            'cov_typ_name' => 'required|string|regex:/^[A-ZÑÁÉÍÓÚÜ ]+$/u',
            'use_id' => 'required|integer|exists:users'
        ];

         // Realizar la validación de los datos recibidos
        $validator = Validator::make($request->input(), $rules);

        // Validar que no exista otro tipo de convenio con el mismo nombre
        $validate = Controller::validate_exists($request->cov_typ_name, 'covenant_types', 'cov_typ_name', 'cov_typ_id', $id);

        // Si la validación falla o ya existe otro tipo de convenio con el mismo nombre, devolver los errores
        if ($validator->fails() || $validate == 0) {
            $msg = ($validate == 0) ? "value tried to register, it is already registered." : $validator->errors()->all();
            return response()->json([
                'status' => False,
                'message' => $msg
            ]);
        } else {

            // Encontrar el tipo de convenio por su ID y actualizar sus datos
            $covenant_type = Covenant_types::find($id);
            $covenant_type->cov_typ_name = $request->cov_typ_name;
            $covenant_type->save();

            // Disparar un nuevo registro
            Controller::NewRegisterTrigger("Se realizo una edición en la tabla contract types", 1, $request->use_id);

            // Devolver una respuesta JSON de éxito
            return response()->json([
                'status' => true,
                'data' => "The contract type with ID: " . $covenant_type->cov_typ_id . " has been updated to '" . $covenant_type->cov_typ_name . "' succesfully.",
            ], 200);
        }
    }
    public function destroy(Covenant_types $covenant_Types)
    {

        // Devolver un mensaje indicando que esta función no está disponible
        return response()->json([
            'status' => false,
            'message' => "Function not available."
        ], 400);
    }
}
