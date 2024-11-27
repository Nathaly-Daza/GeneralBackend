<?php

namespace App\Http\Controllers;

use App\Models\Country;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class CountryController extends Controller
{
    public function index()
    {
        try {
            // Obtener todos los países
            $countries = Country::all();

            // Devolver una respuesta JSON con los países
            return response()->json([
                'status' => true,
                'data' => $countries,
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

        // Reglas de validación para los datos del país
        $rules = [
            'cou_name' => 'required|string|unique:countries|regex:/^[A-ZÑÁÉÍÓÚÜ ]+$/u',
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

            // Crear un nuevo país
            $countries = new Country();
            $countries->cou_name = $request->cou_name;
            $countries->save();

            // Disparar un nuevo registro
            Controller::NewRegisterTrigger("Se realizo una inserción en la tabla countries", 3, $request->use_id);

            // Devolver una respuesta JSON de éxito
            return response()->json([
                'status' => true,
                'message' => "The country '" . $countries->cou_name . "' has been added succesfully."
            ], 200);
        }
    }
    public function show($country)
    {

        // Buscar un país por su ID
        $countries = Country::find($country);

        // Si no se encuentra el país, devolver un mensaje de error
        if (!$countries) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'Could not find the countries you are looking for'],
            ], 400);
        } else {

            // Devolver el país encontrado
            return response()->json([
                'status' => true,
                'data' => $countries,
            ], 200);
        }
    }
    public function update(Request $request, $id)
    {

        // Reglas de validación para actualizar los datos del país
        $rules = [
            'cou_name' => 'required|string|regex:/^[A-ZÑÁÉÍÓÚÜ ]+$/u',
            'use_id' => 'required|integer|exists:users',
        ];

        // Realizar la validación de los datos recibidos
        $validator = Validator::make($request->input(), $rules);

        // Validar que no exista otro país con el mismo nombre
        $validate = Controller::validate_exists($request->cou_name, 'countries', 'cou_name', 'cou_id', $id);

        // Si la validación falla o ya existe otro país con el mismo nombre, devolver los errores
        if ($validator->fails() || $validate == 0) {
            $msg = ($validate == 0) ? "value tried to register, it is already registered." : $validator->errors()->all();
            return response()->json([
                'status' => False,
                'message' => $msg
            ]);
        } else {

            // Encontrar el país por su ID y actualizar sus datos
            $countries = Country::find($id);
            $countries->cou_name = $request->cou_name;
            $countries->save();

            // Disparar un nuevo registro
            Controller::NewRegisterTrigger("Se realizo una edición en la tabla countries", 1, $request->use_id);

            // Devolver una respuesta JSON de éxito
            return response()->json([
                'status' => true,
                'data' => "The country with ID: " . $countries->cou_id . " has been updated to '" . $countries->cou_name . "' succesfully.",
            ], 200);
        }
    }
    public function destroy(Country $country)
    {

        // Devolver un mensaje indicando que esta función no está disponible
        return response()->json([
            'status' => false,
            'message' => "Functions not available"
        ], 400);
    }
}
