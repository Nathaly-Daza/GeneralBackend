<?php

namespace App\Http\Controllers;

use App\Models\NewType;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class NewTypeController extends Controller
{
    public function index()
    {
        try {
            // Intenta obtener todos los tipos de noticias
            $newtypes = NewType::all();
            // Devuelve una respuesta JSON con los tipos de noticias obtenidos
            return response()->json([
                'status' => true,
                'data' => $newtypes
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
        // Reglas de validación para los datos de entrada
        $rules = [
            'new_typ_name' => 'required|string|min:1|max:255|unique:new_types|regex:/^[A-ZÁÉÍÓÚÜÑ ]+$/',
            'use_id' =>'required|integer|exists:users'
        ];
        // Validar los datos de entrada
        $validator = Validator::make($request->input(), $rules);
        if ($validator->fails()) {
            // Si la validación falla, devuelve una respuesta JSON con los errores de validación
            return response()->json([
                'status' => False,
                'message' => $validator->errors()->all()
            ]);
        } else {
            // Crear un nuevo tipo de noticia
            $newtype = new NewType($request->input());
            $newtype->save();
            // Registrar la acción en el sistema
            Controller::NewRegisterTrigger("Se creó un registro en la tabla NewType: $request->new_typ_name", 3, $request->use_id);
            // Devolver una respuesta JSON con un mensaje de éxito
            return response()->json([
                'status' => True,
                'message' => "The newType: ".$newtype->new_typ_name." has been created."
            ],200);
        }
    }
    public function show($id)
    {
        // Buscar el tipo de noticia por su ID
        $newType = NewType::find($id);
        if ($newType == null) {
            // Si el tipo de noticia no se encuentra, devuelve una respuesta JSON con un mensaje de error
            return response()->json([
                'status' => false,
                'data' => ['message' => 'The NewType requested was not found']
            ],400);
        } else {
            // Si se encuentra el tipo de noticia, devuelve una respuesta JSON con los datos del tipo de noticia
            return response()->json([
                'status' => true,
                'data' => $newType
            ]);
        }
    }
    public function update(Request $request, $id)
    {
        // Busca el tipo de noticia por su ID
        $newType = NewType::find($id);

        if ($newType == null) {
            // Devuelve un mensaje de error si el tipo de noticia no se encuentra
            return response()->json([
                'status' => false,
                'data' => ['message' => 'The NewType requested was not found']
            ], 400);
        } else {
            // Define reglas de validación para los datos de entrada
            $rules = [
                'new_typ_name' => 'required|string|min:1|max:255|regex:/^[A-ZÁÉÍÓÚÜÑ ]+$/',
                'use_id' => 'required|integer|exists:users'
            ];

            // Valida los datos de entrada y verifica si el nombre del tipo de noticia ya existe
            $validator = Validator::make($request->input(), $rules);
            $validate = Controller::validate_exists($request->new_typ_name, 'new_types', 'new_typ_name', 'new_typ_id', $id);

            if ($validator->fails() || $validate == 0) {
                $msg = ($validate == 0) ? "value tried to register, it is already registered." : $validator->errors()->all();
                return response()->json([
                    'status' => false,
                    'message' => $msg
                ]);
            } else {
                // Actualiza el nombre del tipo de noticia y guarda los cambios
                $newType->new_typ_name = $request->new_typ_name;
                $newType->save();

                // Registra la acción en el sistema
                Controller::NewRegisterTrigger("Se realizó una edición de datos en la tabla NewType del dato: $id con el dato: $request->new_typ_name", 1, $request->use_id);

                // Devuelve una respuesta JSON con un mensaje de éxito
                return response()->json([
                    'status' => true,
                    'data' => "The newType: ".$newType->new_typ_name." has been updated successfully."
                ], 200);
            }
        }
    }
    // Método para eliminar un tipo de noticia (no disponible en este ejemplo)
    public function destroy(newType $newTypes)
    {
        return response()->json([
            'status' => false,
            'message' => "FUNCTION NOT AVAILABLE"
        ], 400);
    }
}
