<?php

namespace App\Http\Controllers;

use App\Models\History_career;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class HistoryCarrerController extends Controller
{
    public function index()
    {
        try {

            // Seleccionar todos los historiales de las carreras
            $history_careers = History_career::select();

            // Devolver una respuesta JSON con las historias de carrera obtenidas
            return response()->json([
                'status' => true,
                'data' => $history_careers,
            ], 200);
        } catch (\Throwable $th) {

            // Manejar cualquier excepción que pueda ocurrir durante la obtención de las historias de carrera
            return response()->json([
                'status' => false,
                'message' => $th
            ], 500);
        }
    }
    public static function store(Request $request)
    {

        // Definir las reglas de validación para los datos de entrada
        $rules = [
            'car_id' => 'required|integer|exists:careers',
            'stu_id' => 'required|integer|exists:students',
            'use_id' => 'required|integer|exists:users'
        ];

        // Validar los datos de entrada con las reglas definidas
        $validator = Validator::make($request->input(), $rules);
        if ($validator->fails()) {

            // Devolver una respuesta JSON con los errores de validación si falla la validación
            return response()->json([
                'status' => False,
                'message' => $validator->errors()->all()
            ]);
        } else {

            // Crear un historial de carrera con los datos proporcionados
            $history_careers = new History_career();
            $history_careers->car_id = $request->car_id;
            $history_careers->stu_id = $request->stu_id;
            $history_careers->save();

            // Buscar la carrera y el estudiante asociados a la nueva historia de carrera
            $career = History_career::search($history_careers->his_car_id);

            // Disparar la acción de registro
            Controller::NewRegisterTrigger("Se realizo una inserción en la tabla history careers", 3, $request->use_id);

            // Devolver una respuesta JSON indicando que se ha añadido la historia de carrera
            return response()->json([
                'status' => true,
                'message' => "The history career '" . $career->per_name . "' '" . $career->car_name . "' has been added succesfully."
            ], 200);
        }
    }
    public function show($History_career)
    {

        // Buscar una historia de carrera por su ID
        $history_careers = History_career::search_career($History_career);

         // Devolver un mensaje de error si no se encuentra la historia de carrera solicitada
        if (!$history_careers) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'Could not find the history careers you are looking for'],
            ], 400);
        } else {

            // Devolver una respuesta JSON con la historia de carrera encontrada
            return response()->json([
                'status' => true,
                'data' => $history_careers,
            ], 200);
        }
    }

    public function update()
    {
        // Devolver un mensaje de error indicando que la función no está disponible
        return response()->json([
            'status' => false,
            'message' => "Functions not available"
        ], 400);
    }

    public function destroy()
    {
        // Devolver un mensaje de error indicando que la función no está disponible
        return response()->json([
            'status' => false,
            'message' => "Functions not available"
        ], 400);
    }
}
