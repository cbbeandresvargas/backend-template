<?php

namespace App\Http\Controllers;

use App\Models\Files;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Validator;

class FilesController extends Controller
{
    // Agregar un archivo
    public function addFile(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name'  => 'required|string|min:10|max:100',
            'route' => 'required|file|mimes:png,jpeg,jpg,pdf|max:4096',
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 422);
        }

        if ($request->hasFile('route')) {
            $fileRoute = $request->file('route')->storeAs('uploads', uniqid() . '.' . $request->file('route')->extension());

            $file = new Files();
            $file->name = $request->name;
            $file->route = $fileRoute;
            $file->save();

            return response()->json(['message' => 'File added successfully'], 201);
        }

        return response()->json(['error' => 'File upload failed'], 500);
    }

    // Obtener todos los archivos
    public function getFiles()
    {
        $files = Files::all();
        if ($files->isEmpty()) {
            return response()->json(['message' => 'No files found'], 404);
        }

        foreach ($files as $file) {
            $file->route = asset(Storage::url($file->route));
        }

        return response()->json($files, 200);
    }

    // Obtener un archivo por ID
    public function getFileById($id)
    {
        $file = Files::find($id);
        if (!$file) {
            return response()->json(['message' => 'File not found'], 404);
        }

        $file->route = asset(Storage::url($file->route));
        return response()->json($file, 200);
    }

    // Actualizar un archivo por ID
    public function updateFileById($id, Request $request)
    {
        $file = Files::find($id);
        if (!$file) {
            return response()->json(['message' => 'File not found'], 404);
        }

        $validator = Validator::make($request->all(), [
            'name'  => 'sometimes|string|min:10|max:100',
            'route' => 'sometimes|file|mimes:png,jpeg,jpg,pdf|max:4096',
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 422);
        }

        if ($request->has('name')) {
            $file->name = $request->name;
        }

        if ($request->hasFile('route')) {
            if ($file->route && Storage::exists($file->route)) {
                Storage::delete($file->route);
            }

            $fileRoute = $request->file('route')->storeAs('uploads', uniqid() . '.' . $request->file('route')->extension());
            $file->route = $fileRoute;
        }

        $file->save();

        return response()->json(['message' => 'File updated successfully'], 200);
    }

    // Eliminar un archivo por ID
    public function deleteFileById($id)
    {
        $file = Files::find($id);
        if (!$file) {
            return response()->json(['message' => 'File not found'], 404);
        }

        if ($file->route && Storage::exists($file->route)) {
            Storage::delete($file->route);
        }

        $file->delete();

        return response()->json(['message' => 'File deleted successfully'], 200);
    }
}
