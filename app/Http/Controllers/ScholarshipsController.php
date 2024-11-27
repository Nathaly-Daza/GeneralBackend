<?php

namespace App\Http\Controllers;

use App\Models\Scholarship;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;


class ScholarshipsController extends Controller
{
    public function index()
    {
        // Obtener todas las becas desde la base de datos
        $scholarships = Scholarship::all();

        // Retornar una respuesta JSON con las becas obtenidas
        return response()->json([
            'status' => true,
            'data' => $scholarships
        ], 200);
    }
    public function store(Request $request)
    {
        // Definir reglas de validación para los campos de entrada
        $rules = [
            'sch_name' => 'required|string|min:1|max:50|unique:scholarships|regex:/^[A-ZÑÁÉÍÓÚÜ\s]+$/',
            'sch_description' => 'required|string|min:1|max:255',
            'use_id' => 'required|integer|exists:users'
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
            // Crear una nueva instancia de Scholarship y guardarla en la base de datos
            $scholarship = new Scholarship($request->input());
            $scholarship->save();

            // Llamar al método estático NewRegisterTrigger para registrar la acción realizada
            Controller::NewRegisterTrigger("An insertion was made in the scholarships table: $scholarship->sch_id", 3, $request->use_id);

            // Retornar una respuesta JSON indicando que la beca fue creada exitosamente
            return response()->json([
                'status' => true,
                'message' => "The scholarship: " . $scholarship->sch_name . " has been created."
            ], 200);
        }
    }

    public function show($id)
    {
        // Buscar la beca por su ID en la base de datos
        $scholarship = Scholarship::find($id);

        // Verificar si la beca no existe y retornar un mensaje de error si es así
        if ($scholarship == null) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'The scholarship requested not found']
            ], 400);
        } else {
            // Retornar una respuesta JSON con los detalles de la beca encontrada
            return response()->json([
                'status' => true,
                'data' => $scholarship
            ], 200);
        }
    }
    public function update(Request $request, $id)
    {
        // Buscar la beca por su ID en la base de datos
        $scholarship = Scholarship::find($id);

        // Verificar si la beca no existe y retornar un mensaje de error si es así
        if ($scholarship == null) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'The scholarship requested not found.']
            ], 400);
        } else {
            // Definir reglas de validación para los campos de entrada
            $rules = [
                'sch_name' => 'required|string|min:1|max:50|regex:/^[A-ZÑÁÉÍÓÚÜ\s]+$/',
                'sch_description' => 'required|string|min:1|max:255',
                'use_id' => 'required|integer|exists:users'
            ];

            // Ejecutar el validador con las reglas definidas
            $validator = Validator::make($request->input(), $rules);

            // Validar si ya existe otra beca con el mismo nombre en la base de datos
            $exist = Controller::validate_exists($request->sch_name, 'scholarships', 'sch_name', 'sch_id', $id);

            // Verificar si la validación falla o si ya existe una beca con el mismo nombre
            if ($validator->fails() || $exist == 0) {
                $msg = ($exist == 0) ? "value tried to register, it is already registered." : $validator->errors()->all();

                return response()->json([
                    'status' => false,
                    'message' => $msg
                ]);
            } else {
                // Actualizar la beca con los nuevos datos proporcionados
                $scholarship->sch_name = $request->sch_name;
                $scholarship->sch_description = $request->sch_description;

                $scholarship->save();

                // Llamar al método estático NewRegisterTrigger para registrar la acción realizada
                Controller::NewRegisterTrigger("An update was made in the scholarships table: id->$id", 4, $request->use_id);

                // Retornar una respuesta JSON indicando que la beca fue actualizada exitosamente
                return response()->json([
                    'status' => true,
                    'data' => "The scholarship: " . $scholarship->sch_name . " has been updated."
                ], 200);
            }
        }
    }
    public function destroy()
    {
        // Retorna una respuesta JSON indicando que la función no está disponible para este método
        return response()->json([
            'status' => false,
            'message' => "Function not available."
        ], 400);
    }
}
