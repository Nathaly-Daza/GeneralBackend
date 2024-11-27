<?php

namespace App\Http\Controllers;

use App\Models\LearningObjects;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class LearningObjectsController extends Controller
{

    public function index()
    {

        // Obtener todos los objetos de aprendizaje
        $learningObjects = LearningObjects::select();

        // Verificar si no hay objetos de aprendizaje disponibles
        if ($learningObjects == null) {

            // Devolver un mensaje de error si no hay objetos de aprendizaje disponibles
            return response()->json([
                'status' => False,
                'message' => 'There are no learning objects available.'
            ], 400);
        } else {

            // Devolver una respuesta JSON con los objetos de aprendizaje disponibles
            return response()->json([
                'status' => True,
                'data' => $learningObjects
            ], 200);
        }
    }




    public function store(Request $request)
    {

        // Definir las reglas de validación para los datos de entrada
        $rules = [
            'lea_obj_object' => 'required|string|min:5|max:500',
            'cor_mat_id' => 'required|integer|exists:core_material',
            'use_id' => 'required|integer|exists:users'
        ];

        // Validar los datos de entrada con las reglas definidas
        $validator = Validator::make($request->input(), $rules);
        if ($validator->fails()) {

            // Devolver una respuesta JSON con los errores de validación si falla la validación
            return response()->json([
                'status' => False,
                'message' => $validator->errors()->all()
            ], 400);
        } else {

            // Crear un nuevo objeto de aprendizaje con los datos proporcionados
            $learningObject = new LearningObjects($request->input());
            $learningObject->lea_obj_object = $request->lea_obj_object;
            $learningObject->cor_mat_id = $request->cor_mat_id;
            $learningObject->save();

            // Registrar la acción en un sistema de seguimiento
            Controller::NewRegisterTrigger("Se creo un registro en la tabla LearningObject", 3, $request->use_id);

            // Devolver una respuesta JSON indicando que se ha creado el objeto de aprendizaje exitosamente
            return response()->json([
                'status' => True,
                'message' => 'Learning object: ' . $learningObject->lea_obj_object . ' created successfully.',
                'data' => $learningObject
            ], 200);
        }
    }


    public function show($id)
    {

        // Buscar un objeto de aprendizaje por su ID
        $learningObjects = LearningObjects::findOne($id);

        // Verificar si no se encontró el objeto de aprendizaje
        if ($learningObjects == null) {

            // Devolver un mensaje de error si no se encontró el objeto de aprendizaje
            return response()->json([
                'status' => False,
                'message' => 'There are no learning objects available.'
            ], 400);
        } else {

            // Devolver una respuesta JSON con el objeto de aprendizaje encontrado
            return response()->json([
                'status' => True,
                'data' => $learningObjects
            ], 200);
        }
    }


    public function update(Request $request, $id)
    {

        // Buscar el objeto de aprendizaje por su ID
        $learningObject = LearningObjects::find($id);

        // Verificar si no se encontró el objeto de aprendizaje
        if ($learningObject == null) {
            // Devolver un mensaje de error si no se encontró el objeto de aprendizaje
            return response()->json([
                'status' => False,
                'message' => 'There are no learning objects available.'
            ], 400);
        }

        // Definir las reglas de validación para los datos de entrada
        $rules = [
            'lea_obj_object' => ['required', 'regex:/^[A-ZÁÉÍÓÚÜÀÈÌÒÙÑ\s]+$/'],
            'cor_mat_id' => ['required']
        ];

         // Validar los datos de entrada con las reglas definidas
        $validator = Validator::make($request->input(), $rules);
        if ($validator->fails()) {

            // Devolver una respuesta JSON con los errores de validación si falla la validación
            return response()->json([
                'status' => False,
                'message' => $validator->errors()->all()
            ], 400);
        } else {

            // Actualizar el objeto de aprendizaje con los datos proporcionados
            $learningObject->lea_obj_object = $request->lea_obj_object;
            $learningObject->cor_mat_id = $request->cor_mat_id;
            $learningObject->save();

            // Disparar la acción de registro
            Controller::NewRegisterTrigger("Se actualizó un registro en la tabla LearningObject: $request->lea_obj_object ", 3, $request->use_id);

            // Devolver una respuesta JSON indicando que se ha actualizado el objeto de aprendizaje exitosamente
            return response()->json([
                'status' => True,
                'message' => 'Learning object: ' . $learningObject->lea_obj_object . ' updated successfully.',
                'data' => $learningObject
            ], 200);
        }
    }


    public function destroy(Request $request)
    {

        // Devolver un mensaje de error indicando que la función no está permitida
        Controller::NewRegisterTrigger("Se intentó eliminar un dato en la tabla CoreMaterial ", 3, $request->use_id);
        return response()->json([
            'message' => 'This function is not allowed.'
        ], 400);
    }
}
