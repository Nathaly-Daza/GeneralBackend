<?php

namespace App\Http\Controllers;

use App\Models\multiculturalisms;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class MulticulturalismsController extends Controller
{
    public function index()
    {
        try {
            // Intenta obtener todos los multiculturalismos
            $multiculturalism = Multiculturalisms::all();
            // Devuelve una respuesta JSON con los multiculturalismos obtenidos
            return response()->json([
                'status' => true,
                'data' => $multiculturalism
            ],200);
        } catch (\Throwable $th) {
            // Maneja errores y devuelve una respuesta JSON con un mensaje de error
            return response()->json([
                'status' => false,
                'message' => "Error occurred while found elements"
            ],500);
        }
    }
    public function store(Request $request)
    {
        // Define reglas de validación para los datos de entrada
        $rules = [
            'mul_name' => 'required|string|min:1|max:255|unique:multiculturalisms|regex:/^[A-ZÑÁÉÍÓÚÜ\s]+$/',
            'use_id' =>'required|integer|exists:users'
        ];
        // Valida los datos de entrada
        $validator = Validator::make($request->input(), $rules);
        if ($validator->fails()) {
            // Devuelve una respuesta JSON con los errores de validación si la validación falla
            return response()->json([
                'status' => False,
                'message' => $validator->errors()->all()
            ]);
        } else {
            // Crea una nueva instancia de Multiculturalisms con los datos proporcionados
            $multiculturalism = new Multiculturalisms($request->input());
            $multiculturalism->save();
            // Registra la acción en un sistema de seguimiento
            Controller::NewRegisterTrigger("Se creo un registro en la tabla Multiculturalism : $request->mul_name ",3,$request->use_id);
            // Devuelve una respuesta JSON indicando que el multiculturalismo ha sido creado exitosamente
            return response()->json([
                'status' => True,
                'message' => "The multiculturalism: ".$multiculturalism->mul_name." has been created successfully."
            ],200);
        }
    }
     public function show($id)
    {
        // Busca un multiculturalismo por su ID
        $multiculturalism = Multiculturalisms::find($id);
        if ($multiculturalism == null) {
            // Devuelve un mensaje de error si el multiculturalismo no se encuentra
            return response()->json([
                'status' => false,
                'data' => ['message' => 'The searched culturalism was not found']
            ],400);
        } else {
            // Devuelve una respuesta JSON con el multiculturalismo encontrado
            return response()->json([
                'status' => true,
                'data' => $multiculturalism
            ]);
        }
    }
    public function update(Request $request,$id)
    {
        // Busca el multiculturalismo por su ID
        $multiculturalism = Multiculturalisms::find($id);
        if($multiculturalism == null) {
            // Devuelve un mensaje de error si el multiculturalismo no se encuentra
            return response()->json([
                'status' => false,
                'data' => ['message' => 'The searched culturalism was not found']
            ],400);
        } else {
            // Define reglas de validación para los datos de entrada
            $rules = [
                'mul_name' => 'required|string|min:1|max:255|regex:/^[A-ZÑÁÉÍÓÚÜ\s]+$/',
                'use_id' =>'required|integer|exists:users'
            ];
            // Valida los datos de entrada y verifica si el nombre del multiculturalismo ya existe
            $validator = Validator::make($request->input(), $rules);
            $validate = Controller::validate_exists($request->mul_name, 'multiculturalisms', 'mul_name', 'mul_id', $id);
            if ($validator->fails() || $validate == 0) {
                // Devuelve una respuesta JSON con los errores de validación si la validación falla
                $msg = ($validate == 0) ? "value tried to register, it is already registered." : $validator->errors()->all();
                return response()->json([
                    'status' => False,
                    'message' => $msg
                ]);
            } else {
                // Actualiza el multiculturalismo con los datos proporcionados
                $multiculturalism->mul_name = $request->mul_name;
                $multiculturalism->save();
                // Registra la acción en un sistema de seguimiento
                Controller::NewRegisterTrigger("Se realizo una Edicion de datos en la tabla multiculturalisms del dato: $id con el dato: $request->mul_name",1,$request->use_id);
                // Devuelve una respuesta JSON indicando que el multiculturalismo ha sido actualizado exitosamente
                return response()->json([
                    'status' => True,
                    'message' => "The multiculturalism: ".$multiculturalism->mul_name." has been updated successfully."
                ],200);
            }
        }
    }
    public function destroy(multiculturalisms $multiculturalisms)
    {

        // Devuelve un mensaje indicando que la función no está disponible para eliminar un multiculturalismo

        return response()->json([
        'status' => false,
        'message' => "FUNCTION NOT AVAILABLE"
        ],400);
    }
}
