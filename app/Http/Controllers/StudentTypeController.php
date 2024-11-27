<?php

namespace App\Http\Controllers;

use App\Models\Student_types;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class StudentTypeController extends Controller
{
    public function index()
    {
        try {
            // Obtener todos los tipos de estudiantes
            $studentTypes = Student_types::all();

            // Retornar una respuesta JSON con estado verdadero y datos de los tipos de estudiantes
            return response()->json([
                'status' => true,
                'data' => $studentTypes
            ]);
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
        // Definir reglas de validación para los datos del tipo de estudiante a almacenar
        $rules = [
            'stu_typ_name' => 'required|string|min:1|max:255|unique:students_types|regex:/^[A-ZÁÉÍÓÚÜÑ ]+$/',
            'use_id' =>'required|integer|exists:users'
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
            // Crear una nueva instancia de Student_types con los datos del request
            $studentType = new student_types($request->input());
            $studentType->save();

            // Registrar la acción de creación del tipo de estudiante
            Controller::NewRegisterTrigger("Se creo un registro en la tabla student_types : $request->stu_typ_name ", 3, $request->use_id);

            // Retornar una respuesta JSON con estado verdadero y mensaje de éxito
            return response()->json([
                'status' => true,
                'message' => "The student type: ".$studentType->stu_typ_name." has been created successfully."
            ], 200);
        }
    }

    public function show($id)
    {
        // Buscar un tipo de estudiante específico por su ID
        $studentType = student_types::find($id);

        if ($studentType == null) {
            // Retornar una respuesta JSON con estado falso y mensaje de tipo de estudiante no encontrado
            return response()->json([
                'status' => false,
                'data' => ['message' => 'not found student type.']
            ], 400);
        } else {
            // Retornar una respuesta JSON con estado verdadero y datos del tipo de estudiante encontrado
            return response()->json([
                'status' => true,
                'data' => $studentType
            ]);
        }
    }

    public function update(Request $request, $id)
    {
        // Buscar un tipo de estudiante para actualizar por su ID
        $studentType = student_types::find($id);

        if ($studentType == null) {
            // Retornar una respuesta JSON con estado falso y mensaje de tipo de estudiante no encontrado
            return response()->json([
                'status' => false,
                'data' => ['message' => 'not found student type.']
            ], 400);
        } else {
            // Definir reglas de validación para los datos del tipo de estudiante a actualizar
            $rules = [
                'stu_typ_name' => 'required|string|min:1|max:255|regex:/^[A-ZÁÉÍÓÚÜÑ ]+$/',
                'use_id' =>'required|integer|exists:users'
            ];

            // Validar los datos de entrada con las reglas definidas
            $validator = Validator::make($request->input(), $rules);

            // Validar la existencia del nombre del tipo de estudiante para evitar duplicados
            $validate = Controller::validate_exists($request->stu_typ_name, 'students_types', 'stu_typ_name', 'stu_typ_id', $id);

            if ($validator->fails() || $validate == 0) {
                // Retornar una respuesta JSON con estado falso y mensajes de error de validación o de duplicado
                $msg = ($validate == 0) ? "value tried to register, it is already registered." : $validator->errors()->all();
                return response()->json([
                    'status' => false,
                    'message' => $msg
                ]);
            } else {
                // Actualizar el nombre del tipo de estudiante y guardar los cambios
                $studentType->stu_typ_name = $request->stu_typ_name;
                $studentType->save();

                // Registrar la acción de edición del tipo de estudiante
                Controller::NewRegisterTrigger("Se realizo una Edicion de datos en la tabla student $studentType del dato: $id con el dato: $request->stu_typ_name ", 1, $request->use_id);

                // Retornar una respuesta JSON con estado verdadero y mensaje de éxito
                return response()->json([
                    'status' => true,
                    'data' => "The student Type: ".$studentType->stu_typ_name." has been update successfully."
                ], 200);
            }
        }
    }
    public function destroy()
    {
        // Retornar una respuesta JSON indicando que la función no está disponible
        return response()->json([
            'status' => false,
            'message' => "FUNCTION NOT AVAILABLE."
         ], 400);
    }
}
